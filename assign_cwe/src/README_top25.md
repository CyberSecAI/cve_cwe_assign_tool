# Overview

# Methodology



## Proposed LLM Methodology

### Overview
>[!IMPORTANT]
> To ensure an accurate comparison, the existing dataset as used by MITRE CWE Top 25 Methodology should be used.
> 
> This includes the CVE information at the time
>  - CVE publication status / REJECTED
>  - Assigned CWE
>  - CVE Description
>  - CVE Reference links

Broadly, the considerations for comparison:
1. The subset of CVEs in scope as determined by automated analysis
   1. the results from the CWE Top 25 Methodology and Proposed Methodology can be compared
   2. differences can be reviewed
2. The CWEs assigned for the subset of CVEs in scope (per CWE Top 25 Methodology scope) 
   1. the results from the CWE Top 25 Methodology and Proposed Methodology can be compared
3. The CWE corpus and version to map to
   1. View-1003 per NVD that contains 130 CWEs per [CWE Mapping Normalization](https://cwe.mitre.org/top25/archive/2024/2024_methodology.html)
      1. **Is this original mapping available in the dataset or is it VIEW-1003?**
   2. Entire CWE Corpus 
      1. **what version? 4.15?**
4. The datasets
   1. [2024 CWE Top 25 Methodology](https://cwe.mitre.org/top25/archive/2024/2024_methodology.html)
      1. **is this dataset available?**
   2. [2023 CWE Top 25 Methodology](https://cwe.mitre.org/top25/archive/2023/2023_methodology.html)
5. The assigned CWEs
   1. are current assigned CWEs correct? 
      1. i.e. should 1 or more assigned CWEs be changed
   2. are current assigned CWEs complete? 
      1. i.e. are there missing CWEs?
   3. **are the original assigned CWEs available?**

   
### Assess

1. Define the CVEs in scope e.g. Remove REJECTed CVEs
   1. This should be the MITRE CWE Top 25 Methodology scope
2. Pre-Start with a subset of ~~10 CVEs in scope as determined by CWE Top 25 Methodology automated analysis
   1. This acts as a dry run and initial end2end run for feedback and refinement
3. Start with the subset of CVEs in scope as determined by CWE Top 25 Methodology automated analysis
   1. This is ~~30% of the CVEs and gives the best ROI
4. Review existing assigned CWEs and suggest any corrections and additions
   1. Use full CWE corpus
   2. Use Vulnerability Keyphrases from https://github.com/CyberSecAI/cve_info to identify rootcause and impact from the CVE Description
   3. Use CVE reference links (References to Advisories, Solutions, and Tools) info?
      1. **TBD check dataset if it is clear if this was used** from the dataset
   4. The assessment (sufficient info?, too high level?, assigned CWEs correct and complete?) and assignment of CWEs will be done in one pass
5. Provide a report with rationale, chain, similar example CVEs per e.g. https://github.com/cisagov/vulnrichment/issues/112
6. Provide an assessment report in same format as MITRE CWE Top 25 Methodology
   1. one CWE per CVE per line with the chain
      1. e.g. if a CVE has multiple CWEs then each 
   2. how many CVEs had their CWE mappings changed
      1. from a parent CWE to a child CWE
7. Repeat steps 4+ for the remainder of CVEs


### Evaluation Metrics

Define specific metrics to evaluate the LLM's performance:
- Accuracy: Percentage of correct CWE assignments compared to the original mappings.
- Precision: Proportion of correctly identified CWEs out of all CWEs assigned by the LLM.
- Recall: Proportion of actual CWEs in the dataset that were correctly identified by the LLM.
- F1-Score: A harmonic mean of precision and recall.

>[!NOTE] Given the nature of CWEs, it is likely that an assigned CWE is also a candidate right answer
>
> e.g. For https://nvd.nist.gov/vuln/detail/CVE-2023-49224 
> "Precor touchscreen console P62, P80, and P82 contains a default SSH public key in the authorized_keys file. A remote attacker could use this key to gain root privileges." 
> 
> These are similar:
> - [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html). VIEW-1003
> - [CWE-1394: Use of Default Cryptographic Key](https://cwe.mitre.org/data/definitions/1394.html). This is the most appropriate CWE.

**TBD on whether close match, exact match or no match ratings will be used**

**TBD if chains are part of final scoring or ranking.**


## MITRE CWE Top 25 Methodology

>[!TIP] References from 2022 include more technical details and explanation than the 2023 documents:
> - https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html#remapping_task
> - https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25_supplemental.html
> - https://cwe.mitre.org/top25/archive/

### [2024 CWE Top 25 Methodology](https://cwe.mitre.org/top25/archive/2024/2024_methodology.html)
- **31,770** CVE Records for vulnerabilities published between June 1, 2023 and June 1, 2024
- the dataset identified for re-mapping analysis — the “scoped” dataset — contained **9,900** CVE Records (31% of all records in the dataset) originally published by 247 different CNAs.

#### Scope
>The CVE Records were analyzed via automated scanning to identify those that would benefit from re-mapping analysis. These included CVE Records with CWE mappings that:

> Were too high-level
>
> A common mistake made when mapping a vulnerability to a CWE is choosing a high-level entry that is not actionable or precise enough. CWEs at the Base and Variant level ensure adequate specificity, actionability, and root cause information for a vulnerability.

> Differed from a mapping found using an internal keyword matcher
> 
>Over years of Top 25 analysis, the CWE Team has identified a list of keywords found in CVE descriptions that commonly indicate a specific root cause weakness. Although using keywords to identify root cause weaknesses can be flawed, it is a good starting point to identify mappings that could be incorrect. If the keyword matcher found a different mapping than was present, the CVE Record was kept in the dataset for remapping analysis.

### [2023 CWE Top 25 Methodology](https://cwe.mitre.org/top25/archive/2023/2023_methodology.html)

- The “2023 CWE Top 25 Most Dangerous Software Weaknesses” list was calculated by analyzing **public vulnerability data in the U.S. National Vulnerability Database (NVD)** for their root causes via CWE mappings. 
- This year’s list is based on **43,996** CVE Records for vulnerabilities in 2021 and 2022. The mapping data was pulled from the NVD on March 27, 2023.
- the team independently analyzed a subset of **7,466** CVE Records in the total dataset for their root causes mappings. 
- Records were selected via (1) automated keyword analysis of CVE descriptions that suggested inaccurate root cause mappings, or (2) if they mapped to more abstract, high-level CWEs as opposed to more precise root cause mappings. When necessary, the team remapped existing root cause mappings when it seemed that an inconsistent criterion was applied, or a mistake was made in the initial analysis. - The team utilized the entire CWE corpus for these remappings, which are then shared with NIST for confirmation and updating the NVD data.
- In some instances, a sequential series of weaknesses can result in a vulnerability. This creates a root cause mapping “chain”. In this year's analysis, the team attempted to capture chains as best as possible without any changes in the scoring. For any chain "X→Y", both X and Y were included in the analysis as if they were independently listed.


# Examples

>[!NOTE]
> Some of the Top25 contain information from references e.g.
>> CVE-2022-32296,CWE-330,"(Chains: CWE-330->CWE-203) ""weakness in randomisation of TCP source port selection"" in ref ""https://www.debian.org/security/2022/dsa-5173"" and ""servers to identify clients by observing what source ports are used"" in description"
>>
>> - For CVE-2022-32296, https://www.debian.org/security/2022/dsa-5173 contains additional info not in the description.
>>
>> CVE-2022-31459,CWE-328,"ref https://modzero.com/static/meetingowl/Meeting_Owl_Pro_Security_Disclosure_Report_RELEASE.pdf says The SHA-1 hash... can be brute-forced in seconds since it consists only of digits.
>>


Count of instances of `ref` or  `https://` i.e. an extract from the references, not the CVE description:
- ` ref ` 1741
- `https://` 1917
- `commit ref` 173
- `Ref Desc` 90
- `ref has` 308
- `Ref has no other details` 4 


## CVE-2021-0674

### Top25

https://github.com/CyberSecAI/cwe_top25/blob/main/data_in/top25-mitre-mapping-analysis-2023-public.csv
````
CVE-2021-0674,CWE-20,"(Chains: CWE-20->CWE-125) Desc: ""out of bounds read due to an incorrect bounds check""."
CVE-2021-0674,CWE-125,"(Chains: CWE-20->CWE-125) Desc: ""out of bounds read due to an incorrect bounds check""."
````

### CVEProject 

https://github.com/CVEProject/cvelistV5/blob/b81b0ef286ebee200d5f7b1932440774c4cabdd4/cves/2021/0xxx/CVE-2021-0674.json#L49 **does not contain any CWEs**

### CyberSecAI/cve_info

https://github.com/CyberSecAI/cve_info/blob/main/2021/0xxx/CVE-2021-0674.json

```json
    "description": "In alac decoder, there is a possible out of bounds read due to an incorrect bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID ALPS06064258 Issue ID ALPS06064237.",
    "keyphrases": {
        "rootcause": "incorrect bounds check",
        "weakness": "out of bounds read",
        "impact": "local information disclosure",
````

### NVD

https://nvd.nist.gov/vuln/detail/CVE-2021-0674#VulnChangeHistorySection

NVD contains only CWE-125.

CWE Remap by NIST 8/08/2023 10:21:49 AM
````
Action   Type  Old Value  New Value
Changed  CWE   CWE-20     CWE-125
````




## CVE-2021-1047

### Top25

https://github.com/CyberSecAI/cwe_top25/blob/main/data_in/top25-mitre-mapping-analysis-2023-public.csv

````
CVE-2021-1047,CWE-190,"(Chains: CWE-190->CWE-125) Desc: ""out of bounds read due to an integer overflow""."
CVE-2021-1047,CWE-125,"(Chains: CWE-190->CWE-125) Desc: ""out of bounds read due to an integer overflow""."
````

### CVEProject 

https://github.com/CVEProject/cvelistV5/blob/b81b0ef286ebee200d5f7b1932440774c4cabdd4/cves/2021/1xxx/CVE-2021-1047.json#L49 **does not contain any CWEs**


### CyberSecAI/cve_info

https://github.com/CyberSecAI/cve_info/blob/main/2021/1xxx/CVE-2021-1047.json
```json
    "description": "In valid_ipc_dram_addr of cm_access_control.c, there is a possible out of bounds read due to an integer overflow. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation.Product AndroidVersions Android kernelAndroid ID A-197966306References N/A",
    "keyphrases": {
        "rootcause": "integer overflow",
        "weakness": "out of bounds read",
        "impact": "local information disclosure",
````

### NVD

https://nvd.nist.gov/vuln/detail/CVE-2021-1047#VulnChangeHistorySection

NVD contains only CWE-190.

````
Initial Analysis by NIST 12/20/2021 11:04:23 AM


Weakness Enumeration
CWE-ID   CWE                              Name	Source
CWE-190  Integer Overflow or Wraparound   cwe   source acceptance level NIST  
````


## CVE-2022-1016

### Top25

https://github.com/CyberSecAI/cwe_top25/blob/main/data_in/top25-mitre-mapping-analysis-2023-public.csv

````
CVE-2022-1016,CWE-909,"(Chains: CWE-909->CWE-416) ""A flaw found ... which can cause a use-after-free"" in description. seclists ref has ""does not initialize the register data"""
CVE-2022-1016,CWE-416,"(Chains: CWE-909->CWE-416) ""A flaw found ... which can cause a use-after-free"" in description. seclists ref has ""does not initialize the register data"""
````
### CVEProject 
https://github.com/CVEProject/cvelistV5/blob/7312095c493616d19119e504e68e39a4617dfa62/cves/2022/1xxx/CVE-2022-1016.json#L62

Contains CWE-824 under cna Container.

### CyberSecAI/cve_info

https://github.com/CyberSecAI/cve_info/blob/main/2022/1xxx/CVE-2022-1016.json
```json
    "description": "A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.cnft_do_chain, which can cause a use-after-free. This issue needs to handle return with proper preconditions, as it can lead to a kernel information leak problem caused by a local, unprivileged attacker.",
    "keyphrases": {
        "rootcause": "a use-after-free",
        "weakness": "",
        "impact": "kernel information leak",
````



### NVD

NVD contains CWE-909 and CWE-824.

https://nvd.nist.gov/vuln/detail/cve-2022-1016#VulnChangeHistorySection

````

Modified Analysis by NIST 6/27/2023 11:47:56 AM
- Added	CWE		NIST CWE-909
- Removed	CWE	NIST CWE-416

CVE Modified by Red Hat, Inc. 2/12/2023 5:15:22 PM
- Added	CWE		Red Hat, Inc. CWE-824

CVE Modified by Red Hat, Inc. 2/02/2023 4:22:00 PM
- Removed	CWE	Red Hat, Inc. CWE-824

Initial Analysis by NIST 9/08/2022 9:15:48 AM
- Added	CWE		NIST CWE-416

````

### References

https://seclists.org/oss-sec/2022/q1/205
> Root cause CVE-2022-1016: (it is the shortest, so I will begin with it)

> The nft_do_chain routine in net/netfilter/nf_tables_core.c does not initialize the register data that nf_tables expressions can read from- and write to. These expressions inherently exhibit side effects that can be used to determine the register data, which can contain kernel image pointers, module pointers, and allocation pointers depending on the code path taken to end up at nft_do_chain.



## License

> [!NOTE]  
>This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.
> - https://creativecommons.org/licenses/by-sa/4.0/

