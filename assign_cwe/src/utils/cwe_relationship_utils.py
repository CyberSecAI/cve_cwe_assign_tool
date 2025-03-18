# src/retrievers/cwe_relationship_utils.py

from typing import Dict, Any, List
import logging
from utils.logger import get_logger

logger = get_logger(__name__)

def build_bidirectional_relationships(cwe_entries):
    """
    Infer and add reciprocal relationships to the CWE entries since they're not explicitly defined in the XML/JSON.
    
    Args:
        cwe_entries (dict or list): Dictionary of CWE entries keyed by CWE_ID or a list of CWE entry objects
        
    Returns:
        Same type as input (dict or list): Enhanced CWE entries with reciprocal relationships added
    """
    # Map of relationship types to their reciprocals - only these three are bidirectional
    reciprocal_map = {
        "ChildOf": "ParentOf",
        "CanPrecede": "CanFollow", 
        "Requires": "RequiredBy"
    }
    
    logger.info("Building bidirectional CWE relationships")
    
    # Count initial relationship types
    relationship_counts = {}
    
    # Handle both dictionary and list inputs
    is_dict_input = isinstance(cwe_entries, dict)
    
    # If list input, continue with list processing
    if not is_dict_input:
        # Count initial relationships
        for entry in cwe_entries:
            if hasattr(entry, 'RelatedWeaknesses') and entry.RelatedWeaknesses:
                for rel in entry.RelatedWeaknesses:
                    nature = rel.Nature
                    relationship_counts[nature] = relationship_counts.get(nature, 0) + 1
        
        logger.info("Initial relationship counts:")
        for nature, count in sorted(relationship_counts.items()):
            logger.info(f"  {nature}: {count}")
        
        # Create dictionary to store reciprocal relationships
        entries_by_id = {entry.ID: entry for entry in cwe_entries}
        new_relationships = {}
        
        # First pass: identify needed reciprocal relationships
        for entry in cwe_entries:
            if not hasattr(entry, 'RelatedWeaknesses') or not entry.RelatedWeaknesses:
                continue
                
            for rel in entry.RelatedWeaknesses:
                # Skip if no reciprocal defined
                if rel.Nature not in reciprocal_map:
                    continue
                    
                reciprocal_nature = reciprocal_map[rel.Nature]
                target_id = rel.CweID
                
                # Initialize if first relationship for this target
                if target_id not in new_relationships:
                    new_relationships[target_id] = []
                
                # Define the reciprocal relationship
                class ReciprocalRelationship:
                    def __init__(self):
                        self.CweID = entry.ID
                        self.Nature = reciprocal_nature
                        self.ViewID = getattr(rel, 'ViewID', None)
                        self.Ordinal = getattr(rel, 'Ordinal', None)
                
                new_relationships[target_id].append(ReciprocalRelationship())
        
        # Second pass: add reciprocal relationships to appropriate entries
        for target_id, relationships in new_relationships.items():
            if target_id in entries_by_id:
                target_entry = entries_by_id[target_id]
                
                # Initialize RelatedWeaknesses if doesn't exist
                if not hasattr(target_entry, 'RelatedWeaknesses') or target_entry.RelatedWeaknesses is None:
                    target_entry.RelatedWeaknesses = []
                
                # Check for duplicates before adding
                existing_rels = set()
                if target_entry.RelatedWeaknesses:
                    for rel in target_entry.RelatedWeaknesses:
                        rel_key = (rel.CweID, rel.Nature)
                        existing_rels.add(rel_key)
                
                # Add non-duplicate relationships
                for rel in relationships:
                    rel_key = (rel.CweID, rel.Nature)
                    if rel_key not in existing_rels:
                        target_entry.RelatedWeaknesses.append(rel)
                        existing_rels.add(rel_key)
        
        # Count relationships after enhancement
        updated_counts = {}
        for entry in cwe_entries:
            if hasattr(entry, 'RelatedWeaknesses') and entry.RelatedWeaknesses:
                for rel in entry.RelatedWeaknesses:
                    nature = rel.Nature
                    updated_counts[nature] = updated_counts.get(nature, 0) + 1
        
        logger.info("Relationship counts after bidirectional enhancement:")
        for nature, count in sorted(updated_counts.items()):
            logger.info(f"  {nature}: {count}")
        
        return cwe_entries
    
    else:
        # Dictionary input processing
        # Count initial relationships
        for cwe_id, cwe_data in cwe_entries.items():
            relationships = cwe_data.get("relationships")
            if relationships:
                for relationship in relationships:
                    nature = relationship.get("Nature")
                    relationship_counts[nature] = relationship_counts.get(nature, 0) + 1
        
        logger.info("Initial relationship counts:")
        for nature, count in sorted(relationship_counts.items()):
            logger.info(f"  {nature}: {count}")
        
        # Create a dictionary to store the additional reciprocal relationships
        reciprocal_relationships = {}
        
        # Iterate through CWEs and their relationships
        for cwe_id, cwe_data in cwe_entries.items():
            relationships = cwe_data.get("relationships")
            if not relationships:
                continue
                
            for relationship in relationships:
                related_cwe = relationship.get("CWE_ID")
                nature = relationship.get("Nature")
                
                # Skip if no reciprocal is defined
                if not nature or nature not in reciprocal_map:
                    continue
                    
                # Get the reciprocal relationship type
                reciprocal_nature = reciprocal_map[nature]
                
                # Initialize if this is the first reciprocal for this CWE
                if related_cwe not in reciprocal_relationships:
                    reciprocal_relationships[related_cwe] = []
                    
                # Create reciprocal relationship
                reciprocal = {
                    "CWE_ID": cwe_id,
                    "Nature": reciprocal_nature
                }
                
                # Add the reciprocal relationship
                reciprocal_relationships[related_cwe].append(reciprocal)
        
        # Now merge the reciprocal relationships back into the original data
        for cwe_id, relationships in reciprocal_relationships.items():
            if cwe_id in cwe_entries:
                cwe_data = cwe_entries[cwe_id]
                
                if "relationships" not in cwe_data:
                    cwe_data["relationships"] = []
                
                # Track existing relationships to avoid duplicates
                existing_relationships = set()
                for rel in cwe_data["relationships"]:
                    rel_key = (rel["CWE_ID"], rel["Nature"])
                    existing_relationships.add(rel_key)
                
                # Add non-duplicate reciprocal relationships
                for rel in relationships:
                    rel_key = (rel["CWE_ID"], rel["Nature"])
                    if rel_key not in existing_relationships:
                        cwe_data["relationships"].append(rel)
        
        # Count relationships after enhancement
        updated_counts = {}
        for cwe_id, cwe_data in cwe_entries.items():
            if "relationships" in cwe_data and cwe_data["relationships"]:
                for relationship in cwe_data["relationships"]:
                    nature = relationship.get("Nature")
                    updated_counts[nature] = updated_counts.get(nature, 0) + 1
        
        logger.info("Relationship counts after bidirectional enhancement:")
        for nature, count in sorted(updated_counts.items()):
            logger.info(f"  {nature}: {count}")
        
        return cwe_entries