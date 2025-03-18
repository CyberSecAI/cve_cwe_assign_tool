# src/models/cwe.py

#    """Represents a complete CWE entry"""
#    ID: str = Field(..., description="CWE identifier")
#    Name: str = Field(..., description="Name of the weakness")
#    Abstraction: str = Field(..., description="Abstraction level")
#    #Structure: str = Field(..., description="Structure type")
#    Status: str = Field(..., description="Current status")
#    Description: str = Field(..., description="Main description")
#    ExtendedDescription: Optional[str] = Field(None, description="Extended details")
#    #LikelihoodOfExploit: Optional[str] = Field(None, description="Exploitation likelihood")
#    #BackgroundDetails: Optional[List[str]] = Field(None, description="Background information")
#    AlternateTerms: Optional[List[AlternateTerm]] = Field(None, description="Alternative terms")
#    #ModesOfIntroduction: Optional[List[ModeOfIntroduction]] = Field(None, description="Introduction modes")
#    #ApplicablePlatforms: Optional[List[ApplicablePlatform]] = Field(None, description="Applicable platforms")
#    #CommonConsequences: Optional[List[CommonConsequence]] = Field(None, description="Common consequences")
#    #DetectionMethods: Optional[List[DetectionMethod]] = Field(None, description="Detection methods")
#    #PotentialMitigations: Optional[List[PotentialMitigation]] = Field(None, description="Potential mitigations")
#    #DemonstrativeExamples: Optional[List[DemonstrativeExample]] = Field(None, description="Demonstrative examples")
#    ObservedExamples: Optional[List[ObservedExample]] = Field(None, description="Observed examples")
#    RelatedWeaknesses: Optional[List[RelatedWeakness]] = Field(None, description="Related CWEs")
#    #WeaknessOrdinalities: Optional[List[WeaknessOrdinality]] = Field(None, description="Weakness ordinalities")
#    MappingNotes: Optional[MappingNote] = Field(None, description="Mapping notes")
#    Notes: Optional[List[Note]] = Field(None, description="Additional notes")
#    #RelatedAttackPatterns: Optional[List[str]] = Field(None, description="Related attack patterns")


#  <xs:sequence>
#  <xs:element name="Usage" type="cwe:UsageEnumeration" minOccurs="1" maxOccurs="1"/>
#  <xs:element name="Rationale" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
#  <xs:element name="Comments" type="cwe:StructuredTextType" minOccurs="1" maxOccurs="1"/>
#  <xs:element name="Reasons" type="cwe:ReasonsType" minOccurs="1" maxOccurs="1"/>
#  <xs:element name="Suggestions" type="cwe:SuggestionsType" minOccurs="0" maxOccurs="1"/>
#  </xs:sequence>
#  
#  <xs:simpleType name="UsageEnumeration">
#  <xs:annotation>
#  <xs:documentation>The UsageEnumeration simple type is used for whether this CWE entry is supported for mapping.</xs:documentation>
#  </xs:annotation>
#  <xs:restriction base="xs:string">
#  <xs:enumeration value="Discouraged">
#  <xs:annotation>
#  <xs:documentation>this CWE ID should not be used to map to real-world vulnerabilities</xs:documentation>
#  </xs:annotation>
#  </xs:enumeration>
#  <xs:enumeration value="Prohibited">
#  <xs:annotation>
#  <xs:documentation>this CWE ID must not be used to map to real-world vulnerabilities</xs:documentation>
#  </xs:annotation>
#  </xs:enumeration>
#  <xs:enumeration value="Allowed">
#  <xs:annotation>
#  <xs:documentation>this CWE ID may be used to map to real-world vulnerabilities</xs:documentation>
#  </xs:annotation>
#  </xs:enumeration>
#  <xs:enumeration value="Allowed-with-Review">
#  <xs:annotation>
#  <xs:documentation>this CWE ID could be used to map to real-world vulnerabilities in limited situations requiring careful review</xs:documentation>
#  </xs:annotation>
#  </xs:enumeration>



     # Top25Examples

# src/models/cwe.py
from typing import List, Dict, Optional, Set, Any, Union
from pydantic import BaseModel, Field, ConfigDict
import json
import logging

logger = logging.getLogger(__name__)

class AlternateTerm(BaseModel):
    """Represents alternative terminology."""
    model_config = ConfigDict(
        validate_assignment=True,
        extra='allow'
    )
    
    Term: str = Field(..., description="The alternate term")
    Description: Optional[str] = Field(None, description="Description of term")

class ObservedExample(BaseModel):
    """Represents an observed example."""
    model_config = ConfigDict(
        validate_assignment=True,
        extra='allow'
    )
    
    Reference: str = Field(..., description="Reference ID")
    Description: str = Field(..., description="Description of example")
    Link: Optional[str] = Field(None, description="Link to more information")

class Top25Example(BaseModel):
    """Represents a Top 25 CWE example."""
    model_config = ConfigDict(
        validate_assignment=True,
        extra='allow'
    )
    
    Reference: str = Field(..., description="Reference ID (CVE)")
    Description: str = Field(..., description="Description of example")
    Year: str = Field(..., description="Year of Top 25 list")

class RelatedWeakness(BaseModel):
    """Represents a relationship to another CWE."""
    model_config = ConfigDict(
        validate_assignment=True,
        extra='allow'
    )
    
    Nature: str = Field(..., description="Nature of the relationship")
    CweID: str = Field(..., description="ID of the related CWE")
    ViewID: str = Field(..., description="View ID")
    Ordinal: Optional[str] = Field(None, description="Ordinal value")

class CWEEntry(BaseModel):
    """Enhanced CWE entry with optimized text representation."""
    model_config = ConfigDict(
        validate_assignment=True,
        extra='allow',
        arbitrary_types_allowed=True
    )
    
    ID: str = Field(..., description="CWE identifier")
    Name: str = Field(..., description="Name of the weakness")
    Abstraction: str = Field(..., description="Abstraction level")
    Status: str = Field(..., description="Current status")
    Description: str = Field(..., description="Main description")
    ExtendedDescription: Optional[str] = Field(None, description="Extended details")
    AlternateTerms: Optional[List[AlternateTerm]] = Field(None, description="Alternative terms")
    ObservedExamples: Optional[List[ObservedExample]] = Field(None, description="Observed examples")
    Top25Examples: Optional[List[Top25Example]] = Field(None, description="Top 25 CWE examples")
    RelatedWeaknesses: Optional[List[RelatedWeakness]] = Field(None, description="Related CWEs")
    
    # Store complex fields as Any to avoid validation issues
    MappingNotes: Optional[Any] = Field(None, description="Mapping notes")
    Notes: Optional[Any] = Field(None, description="Additional notes")
    PotentialMitigations: Optional[Any] = Field(None, description="Potential mitigations")

    def to_searchable_text(self) -> str:
        """Convert CWE entry to unified searchable text format."""
        sections = []
        
        # Core Information
        sections.append(f"CWE-{self.ID}: {self.Name}")
        sections.append(f"Type: {self.Abstraction}")
        sections.append(f"Status: {self.Status}")
        
        # Primary Content
        sections.append("Description:")
        sections.append(self.Description)
        
        if self.ExtendedDescription:
            sections.append("Extended Details:")
            sections.append(self.ExtendedDescription)
        
        # Alternate Terms
        if self.AlternateTerms:
            terms = []
            for term in self.AlternateTerms:
                if term.Description:
                    terms.append(f"{term.Term} - {term.Description}")
                else:
                    terms.append(term.Term)
            if terms:
                sections.append("Alternative Terms:")
                sections.append("\n".join(terms))
        
        # Examples
        if self.ObservedExamples:
            sections.append("Real-World Examples:")
            for example in self.ObservedExamples:
                sections.append(f"- {example.Reference}: {example.Description}")
        
        # Top 25 Examples
        if self.Top25Examples:
            sections.append("Top 25 CWE Examples:")
            for example in self.Top25Examples:
                sections.append(f"- {example.Reference}: {example.Description}")
        
        # Related Weaknesses
        if self.RelatedWeaknesses:
            sections.append("Related Weaknesses:")
            for weakness in self.RelatedWeaknesses:
                sections.append(f"- CWE-{weakness.CweID} ({weakness.Nature})")
        
        return "\n\n".join(sections)

    def to_embedding_data(self) -> Dict[str, Any]:
        """Generate structured data for embedding."""
        return {
            'id': f"CWE-{self.ID}",
            'name': self.Name,
            'type': self.Abstraction,
            'description': self.Description,
            'extended_description': self.ExtendedDescription,
            'status': self.Status,
            'metadata': {
                'alternate_terms': [
                    {'term': term.Term, 'description': term.Description}
                    for term in (self.AlternateTerms or [])
                ],
                'observed_examples': [
                    {'reference': ex.Reference, 'description': ex.Description}
                    for ex in (self.ObservedExamples or [])
                ],
                'top25_examples': [
                    {'reference': ex.Reference, 'description': ex.Description, 'year': ex.Year}
                    for ex in (self.Top25Examples or [])
                ],
                'related_weaknesses': [
                    {'cwe_id': w.CweID, 'nature': w.Nature}
                    for w in (self.RelatedWeaknesses or [])
                ]
            }
        }

def load_cwe_database(json_path: str) -> List[CWEEntry]:
    """Load and parse CWE entries from a JSON file"""
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
            
        entries = []
        for entry_data in data.get('Weaknesses', []):
            try:
                entry = CWEEntry(**entry_data)
                entries.append(entry)
            except Exception as e:
                logger.error(f"Error parsing CWE entry {entry_data.get('ID', 'unknown')}: {e}")
                
        logger.info(f"Successfully loaded {len(entries)} CWE entries")
        return entries
    except Exception as e:
        logger.error(f"Error loading CWE database from {json_path}: {e}")
        raise