RME ACS Issue C.a Rule Checklist
================================

Source specification: `RME System Architecture specification <https://developer.arm.com/documentation/den0129/latest/>`_.

This page provides a short summary of the RME ACS Issue C.a rule checklist. The checklist itself is maintained as CSV so that GitHub can render it directly as a table and partners can download the same file for spreadsheet use.

Checklist source: `Arm_RME_System_ACS_Testcase_Checklist.csv <Arm_RME_System_ACS_Testcase_Checklist.csv>`_.

Summary
-------

.. csv-table::
   :header: "Category", "Count"
   :widths: 28, 12

   "Total rule IDs listed", "222"
   "Implemented", "104"
   "Future implementation", "27"
   "Out of scope", "91"

Checklist Data
--------------

Open `Arm_RME_System_ACS_Testcase_Checklist.csv <Arm_RME_System_ACS_Testcase_Checklist.csv>`_ to view the full checklist table in GitHub.

To update the checklist, edit the CSV file. If rule status counts change, update the summary table on this page as well.

.. checklist-table-start

.. csv-table:: RME ACS Issue C.a Rule Checklist
   :header: "Sl No", "Rule ID", "Rule Description", "Status", "Notes"
   :widths: 8, 14, 48, 18, 36

   1,RDFYXL,"In an RME system, any access by a requester and any instruction executed by a PE is associated with a single Security state.",Out of Scope,Broad architectural invariant; ACS validates observable access behavior in other tests.
   2,RQDWVC,Association of a Resource with a Resource PAS is controlled by either SSD or MSD.,Out of Scope,Resource ownership control is SSD/MSD policy and implementation-specific.
   3,RBJVZS,Resource accesses carry an Access PAS and MECID as required by the architecture.,Implemented,
   4,RYXFMV,Requesters outside MMU/SMMU translation are SSD-tagged with an Access PAS.,Out of Scope,Requires DAP/debug-access support to generate and tag non-MMU/SMMU requests.
   5,RSCDLL,"Once assigned, the value of an Access PAS cannot be altered.",Out of Scope,Access PAS tag mutation is internal behavior and not directly observable by ACS.
   6,RYKVJK,A PAS filter enforces the PAS protection check by permitting access to a Resource only if the Access PAS matches a Resource PAS associated with that Resource.,Implemented,
   7,RMZJXC,Every requester in the system is subjected to the PAS protection check.,Implemented,
   8,RWRGTF,Access to the Root PAS is only permitted for Trusted requesters.,Out of Scope,Trusted requester access policy is not generically observable by ACS.
   9,RKGDVK,GPT-based PAS assignment requires a single PA per PAS and page-granular resources.,Implemented,
   10,RWJNMD,On-chip Resource GPC relies only on GPT storage with equivalent integrity and replay protection.,Out of Scope,"GPT storage location, integrity, and replay protection are implementation details."
   11,RGQCQT,GPC-protected non-idempotent accesses are not speculatively performed before the check completes.,Out of Scope,Non-idempotent speculation behavior is not directly software-observable.
   12,RGFGZM,"If a requester-side Granular PAS filter is in reset state, any requester that is associated with it is either in reset state or blocked from accessing memory.",Implemented,
   13,RWFQKD,A PA that targets memory that can be cached is associated with a PAS until reaching the PoPA.,Implemented,
   14,RFRMJJ,"Where a PA is associated with a PAS, any PA compare operation includes the PAS.",Implemented,
   15,RQBNJF,"A PoPA CMO affects all cached copies for the specified {PAS, PA}, independent of shareability domain or MECID.",Implemented,
   16,RTRBZM,An access to a cacheable memory Location is associated with a MECID until reaching the PoE.,Implemented,
   17,RKMNQX,"Memory accesses resulting from a cache Clean operation, due to cache maintenance operations and natural evictions, use the MECID that the entry was cached with.",Implemented,
   18,RMLFBL,"External Secure, Realm, and Root memory is encrypted with distinct contexts and address tweaks.",Implemented,
   19,RMYWVB,Data is encrypted before being written to external memory or to any shared cache that resides past the PoPA.,Implemented,
   20,RRQZBK,"Memory-mapped data structures that store encryption contexts must reside in SMEM in the Root PAS, such as MSD SMEM.",Out of Scope,MEC encryption-context storage is not generically discoverable by ACS.
   21,RBNSQB,ECC-scrubbing engines beyond PoPA must not leak confidential information.,Out of Scope,ECC scrubber behavior depends on implementation-specific RAS logic.
   22,RGDVSZ,A PA of an access to a memory-mapped peripheral is associated with a PAS until reaching the PAS filter assigned to protect the peripheral.,Implemented,
   23,RDVPGT,A private PAS filter allows access to a register only if the Access PAS matches a Resource PAS that the register is associated with.,Implemented,
   24,RRHBJN,Non-PE requesters use the permitted RME Security states.,Out of Scope,Non-PE requester security-state behavior is implementation-specific.
   25,RMCMSH,"A fully coherent non-PE requester that is not part of the System Security Domain (SSD) will not observe coherency traffic for addresses in the Secure, Realm, or Root PAS.",Out of Scope,Generic ACS infrastructure does not support coherent-device traffic visibility.
   26,RRGQRT,Programmable all-PAS completer filters keep controls in Root PAS and reset safely.,Out of Scope,Completer-side PAS filter controls are implementation-defined.
   27,RGLLZY,Secure/Non-secure completer filters keep controls in Secure or Root PAS and reset safely.,Out of Scope,Completer-side PAS filter controls are implementation-defined.
   28,RWBJJT,TSM functionality in RME-DA is implemented within RMSD.,Out of Scope,TSM/RMM software presence is outside hardware ACS scope.
   29,RQRMPD,Realm-assigned TDI translated accesses are subject to DPT checks unless exempted.,Implemented,
   30,RPGSTQ,Measured integrated TDISP devices may skip DPT checks but not GPC.,Implemented,
   31,RSHRMN,RME-DA coherent links attach only permitted coherent devices and cover attestation-relevant logic.,Future Implementation,
   32,RNVWMC,"RME-CDA coherent devices support compliant TDI assignment, encryption, MEC, and coherency behavior.",Future Implementation,
   33,RQWNBN,A TDI in TDISP ERROR state poisons relevant Realm cached data and snoop responses.,Future Implementation,
   34,RLMFLX,"A TDI entering CONFIG_UNLOCKED invalidates device-held TDI state, cache copies, and ATC entries.",Implemented,
   35,RVPKVF,Required coherent-device operations are unaffected by TDI state.,Future Implementation,
   36,RWFYLW,Security-sensitive RME-CDA device registers are DSM-controlled or DSM-verified before lock.,Future Implementation,
   37,RJZQCP,RME coherent devices protect Realm state on reset or power transitions.,Implemented,
   38,RHDXTM,A TDI entering CONFIG_UNLOCKED scrubs all associated DCM contents.,Future Implementation,
   39,RKRCWK,"An access from a PE to any memory location, including to DCM, is subject to host-side GPC.",Implemented,
   40,RQRMSC,DCM access follows host-side GPC or device-side PAS checks based on PAS_CHECK.,Future Implementation,
   41,RWWBPM,An RME-CDA coherent device does not permit an internal access to DCM to specify Access PAS == Realm if the access is not from a TDI in the RUN TDISP state.,Future Implementation,
   42,RFZBMW,An RME-CDA coherent device does not permit an external access to DCM to specify Access PAS == Realm if the access did not arrive over an IDE Stream provisioned through TDISP.,Future Implementation,
   43,RKNZGC,Device-side PAS checks block speculative access to read-sensitive locations until complete.,Future Implementation,
   44,RVHZCR,"If PAS_CHECK == TRUE, device-side PAS protection checks apply both to internal access and external access to DCM.",Future Implementation,
   45,RSTQHS,Hosts forward snoops to coherent devices only when the device is permitted to observe the location.,Future Implementation,
   46,RHTTNB,Host ports return poison/fixed data when blocked snoops might otherwise expose dirty device-owned data.,Future Implementation,
   47,RYDSYL,RME-CDA devices set CHI SEC_SID and RID correctly for TDI device-to-host requests.,Future Implementation,
   48,RSKJNK,RME-CDA device-to-host PAs are obtained through ATS or an equivalent host translation protocol.,Future Implementation,
   49,RYJVJR,An SMMU in an RME-CDA system supports populating the TE Memory Attribute bit (TE bit) in ATS Translation completions with the resolved PA space.,Future Implementation,
   50,RFRFJG,An RME-CDA coherent device guarantees that a TDI can generate device-to-host snoop requests only to PAs that it is allowed to directly access.,Future Implementation,
   51,RNSMGT,A host port must be able to identify that a PA of a device-to-host access falls within the DCM range of the coherent device attached to that port.,Future Implementation,
   52,RSHSXK,Host ports apply GPC and Realm DPT checks to relevant device-to-host PA requests.,Future Implementation,
   53,RDMSPT,Host ports check device-to-host Requester IDs against the permitted RID range.,Future Implementation,
   54,RJSYPS,Host ports apply DCM range handling for device-to-host snoop requests and skip GPC/DPT for them.,Future Implementation,
   55,RHVCNR,Devices handle blocked insecure snoops consistently with receiving poisoned snoop responses.,Future Implementation,
   56,RZTQYT,RME-CDA coherent devices must not send DVM CHI requests.,Out of Scope,Requires CHI/C2C opcode trace visibility; ACS cannot prove absence from software.
   57,RDRVTK,Device-to-host traffic uses only MECIDs permitted for the device.,Future Implementation,
   58,RJSDVG,All structures and fields defined by this specification use little-endian convention.,Implemented,
   59,RCSSDG,MSD SMEM is in the Root PAS.,Implemented,
   60,RSPLKT,The address ranges of MSD SMEM are either defined statically or defined by SSD following an RME system reset.,Out of Scope,MSD SMEM address definition is platform/SSD policy.
   61,RNXJLB,On an RME system reset MSD SMEM is either immediately assigned to the Root PAS or scrubbed and is available for access by the PE boot ROM as soon as it starts executing.,Implemented,
   62,RCMMCZ,RMSD SMEM is in the Realm PAS.,Implemented,
   63,RZVQGS,The address ranges of SMEM assigned to the Realm PAS and Secure PAS are either defined statically or by SSD or MSD.,Out of Scope,SMEM address definition is platform/SSD/MSD policy.
   64,RZQQSQ,SMEM that can be dynamically assigned to the Realm PAS or the Secure PAS is either immediately assigned to the Root PAS or scrubbed on an RME system reset.,Implemented,
   65,RZCJHY,The access control path that protects SMEM is not affected by state from non-shielded memory.,Out of Scope,SMEM protection path details are implementation-specific.
   66,RGSRPS,All A-profile application PEs in the system implement the Realm Management Extension (RME).,Implemented,
   67,RNJRPC,"An SMMU in an RME system complies with SMMU for RME [3] and, if the system supports RME-DA or MEC, with SMMU for RME-DA.",Implemented,
   68,RPXDQJ,"In a system that supports RME-DA, any access from a TDISP-compliant device is subject to SMMU translation.",Future Implementation,
   69,RXBKYB,All bus and interconnect decoding components between the point where the Access PAS is assigned and the PoPA are PAS tag-aware.,Out of Scope,Bus/interconnect PAS-awareness is covered indirectly by access behavior.
   70,RXTSXB,An RME coherent interconnect supports cache maintenance operations to the PoPA in compliance with the Arm A-profile architecture [1].,Implemented,
   71,RFXQCD,"A PoPA CMO applies to any cache before the PoPA, including system caches that are located beyond the Point of Coherency.",Implemented,
   72,RLCXDB,Completion of a PoPA CMO cleans dirty state beyond PoPA and invalidates cached state before PoPA.,Implemented,
   73,RCMMDG,"For any cache before the PoPA, cache prefetching across granule-boundary is allowed only after querying the GPC for the PAS association of the next granule.",Out of Scope,Cache prefetch behavior is not directly software-observable.
   74,RPSGCM,A cache maintenance operation performed on a Clean cache entry never results with a write of entry content past the PoPA.,Out of Scope,Clean-cache writeback behavior is not directly software-observable.
   75,RJRJSQ,An RME coherent interconnect complies with a Distributed Virtual Memory (DVM) version that supports Realm Translation Regimes and TLB Invalidate by PA operations.,Implemented,
   76,RDNFTD,A PA of an access to a PCIe Root Port is associated with a PAS until reaching the Root Port.,Implemented,
   77,RTTPLM,Interconnect registers that control mapping of PAs to PCIe Root Ports are implemented as MSD-Protected registers (MPRs).,Implemented,
   78,RXZTPC,"RME-DA host bridge BDF, ECAM, and memory-range assignments are static or trusted-controlled.",Future Implementation,
   79,RKSPKN,Encryption keys or any other confidential memory encryption context that is used by an MPE are stored in registers that are reset to a known default value on an RME system reset.,Out of Scope,MPE key storage is implementation-defined and not directly observable.
   80,RQDPVN,Any PAS other than the Non-secure PAS must have encryption enabled.,Implemented,
   81,RVSMPS,The decision to enable encryption for the Non-secure PAS is either hardwired or defined at boot and immutable once set.,Implemented,
   82,RYHXPH,An MPE integrity error is reported as an external abort to a software or hardware agent consuming the error.,Out of Scope,MPE integrity error delivery depends on implementation-specific error injection.
   83,RYJDSJ,Any captured details of an MPE integrity error are only visible to MSD.,Out of Scope,MPE error capture visibility is implementation-specific.
   84,RLPQSN,An MPE property that is reported through the System Properties structure in Root Non-volatile Storage (RNVS) is supported for all external memory ports in the system.,Out of Scope,RNVS-reported MPE properties are implementation-defined.
   85,RSXCFK,A Trusted SCP is an on-chip control processor that is trusted by MSD and can access resources in the Root PAS.,Out of Scope,Trusted SCP may be non-A-profile trusted hardware.
   86,RZHJQJ,A Trusted SCP is a Trusted subsystem and meets the applicable CCA security requirements.,Out of Scope,Trusted SCP may be non-A-profile trusted hardware.
   87,RMZDXV,It is permitted for a Trusted SCP to have a mechanism to bypass a PAS filter that filters its transactions.,Out of Scope,Trusted SCP may be non-A-profile trusted hardware.
   88,RLGXBX,An RME-DA RP sets the TEE-IO Supported bit in the Device Capabilities Register.,Implemented,
   89,RGRCKL,RME-DA Root Ports support the required Selective IDE Stream features.,Implemented,
   90,RBDLXG,An RME-DA RP exposes an IMPLEMENTATION DEFINED IDE key programming interface for the following IDE Key Management (IDE_KM) data objects:; KEY_PROG.; K_SET_GO.; K_SET_STOP.,Out of Scope,IDE key programming interface is implementation-defined.
   91,RVCRRM,An RME-DA RP must support IDE key refresh operations in compliance with [4].,Out of Scope,IDE key refresh requires implementation-specific software support.
   92,RFSFST,RP IDE logic detects when an IDE key set requires refresh and either signals Trusted firmware or makes the stream Insecure.,Out of Scope,IDE key refresh detection is implementation-defined and not software-observable.
   93,RBWFTS,RMSD ensures that Selective IDE Streams are configured such that different streams are assigned RID ranges and address ranges that do not overlap.,Out of Scope,"IDE stream range allocation is RMSD/RMM policy, not generic ACS behavior."
   94,RDVJRV,The RME-DA DVSEC implements the required PCIe register layout.,Implemented,
   95,RXHMDQ,"When TDISP is enabled, security-sensitive RP registers are RMSD write-protect.",Implemented,
   96,RNXJKQ,"When TDISP is enabled, IDE keys, confidential state, and protected payload registers are RMSD full-protect.",Implemented,
   97,RPCRFM,"When TDISP is enabled, protected RP configuration registers are RMSD write-detect.",Implemented,
   98,RHCMWC,"When RMEDA_CTL1.TDISP_EN transitions from 1 to 0, all hosted IDE Streams transition to IDE Insecure state.",Implemented,
   99,RRNQNM,"When TDISP is disabled, Root Ports clear/reject protected T-bit or XT-bit traffic.",Implemented,
   100,RNPGJV,The RMEDA_CTL registers are RMSD write-protect by hardware default.,Implemented,
   101,RNWSJB,All RPs in an RME-DA system must implement the RME-DA DVSEC.,Implemented,
   102,RYHQQL,Selective IDE register-block lock state controls register protection and stream lock state.,Implemented,
   103,RGKHSZ,RME-DA Root Ports associate outgoing TLPs with IDE streams and set T-bit/XT-bit correctly.,Implemented,
   104,RCFQBW,An RME-DA RP sets the IDE T-bit for an outgoing PCIe Memory Request or Configuration Request based on the request PAS.,Implemented,
   105,RSWBSV,"Root Ports set the IDE T-bit on PCIe messages according to DTI, VDM, and message type.",Out of Scope,PCIe message IDE T-bit requires packet visibility not available to ACS.
   106,RCKJMN,PCIe completions set IDE T-bit according to IDE and TDISP rules.,Out of Scope,PCIe completion IDE T-bit is not software-observable in generic ACS.
   107,RDVKPF,Protected outgoing T-bit/XT-bit requests are rejected unless bound to a locked Secure IDE stream.,Implemented,
   108,RKZBHV,"With TDISP enabled, Root Ports allow protected incoming T-bit/XT-bit requests only when permitted.",Implemented,
   109,RMYKFH,"Root Ports map incoming requests to SMMU SEC_SID, StreamID, and SubstreamID correctly.",Implemented,
   110,RMDPKR,Root Complex P2P completions are returned only from the intended target peer.,Implemented,
   111,RLMFSV,TDISP-enabled Root Port debug features are disabled unless explicitly authorized.,Out of Scope,Root Port debug functionality is implementation-defined.
   112,RGSTJC,Security-affecting RP reset or state loss transitions hosted IDE streams to Insecure.,Implemented,
   113,RMJNLW,Requests that are autonomously initiated by the RP over its host interface are tagged with PAS == Non-secure.,Implemented,
   114,RPJGJK,Root Ports poison affected TLPs or transition IDE streams to Insecure on integrity errors.,Implemented,
   115,RMJSFF,"An RME system must not include an SMMU that supports the XT extensions, unless all RPs either support the XT extensions or override the XT-bit to 0 for incoming requests.",Future Implementation,
   116,RJXRNG,TDISP XT-capable Root Ports set XT-bit behavior according to XT enablement and traffic type.,Future Implementation,
   117,RGBVTS,"As a completer of memory requests, a TDISP-compliant RCiEP extracts the request IDE T-bit from the request PAS.",Implemented,
   118,RZJJMZ,"RCiEP requesters set SEC_SID, StreamID, and SubstreamID according to T-bit and requester identity.",Implemented,
   119,RQNTYC,The PCIe segment and RIDs that are allocated to an RCiEP are either defined statically or configured using an RMSD write-protect register.,Out of Scope,PCIe segment/RID ownership is static or RMSD-protected and not generically modifiable.
   120,RGBGQX,Exposed CTC coherent links support cryptographic encryption and integrity protection.,Implemented,
   121,RDFWKW,A coherent host port that supports RME-CDA implements the Coherent RME-DA DVSEC (RME-CDA DVSEC).,Implemented,
   122,RHMXTF,Coherent host-port system address ranges are controlled by HDM decoders or RMSD-protected registers.,Implemented,
   123,RGVRQC,The RME-CDA DVSEC implements the required PCIe register layout.,Implemented,
   124,RVSFPJ,"With CDA TDISP enabled, security-sensitive coherent host-port registers are RMSD write-protect.",Implemented,
   125,RPHCGC,"With CDA TDISP enabled, IDE keys, confidential state, and protected payload registers are RMSD full-protect.",Implemented,
   126,RFDVZC,"When RMECDA_CTL1.TDISP_EN transitions from 1 to 0, all IDE Streams transition to IDE Insecure state.",Implemented,
   127,RNYCLL,"When CDA TDISP is disabled, Realm device/host memory requests are rejected.",Implemented,
   128,RWPGJB,The RMECDA_CTL registers are RMSD write-protect by hardware default.,Implemented,
   129,RPLYKV,All host ports in a system that supports Coherent RME-DA implement the RME-CDA DVSEC.,Implemented,
   130,RDHNWR,Coherent Link IDE lock state controls register protection and stream lock state.,Implemented,
   131,RWYVCQ,Unlocked coherent link streams reject Realm host-to-device requests.,Implemented,
   132,RGTVGZ,"With CDA TDISP enabled, Realm device-to-host requests are permitted only on locked active links or equivalent safe paths.",Implemented,
   133,RXQHNG,Locked CDA host ports reject out-of-range or invalid Requester IDs.,Implemented,
   134,RLQMCY,"In an RME system, if a Type-3 memory expansion device does not support target-side memory encryption then its memory must be encrypted by a host-side MPE.",Implemented,
   135,RHCQWS,A host-side MPE shall comply with initiator-based memory encryption requirements specified in CXL-TSP.,Implemented,
   136,RXWJNN,Exposed CXL memory-expansion links use CXL IDE link protection.,Implemented,
   137,RCNSLJ,Type-3 CXL devices without CXL-TSP are allowed only when host-side protection conditions are met.,Implemented,
   138,RHHMVM,CXL Root Ports without active CDA TDISP tag back-invalidate snoops as Non-secure.,Implemented,
   139,RPTGGP,CMOs targeting CXL Type-3 memory reach all relevant host-side and device-side cache locations.,Implemented,
   140,RBYTYV,CXL Root Ports either support RME-CDA DVSEC or force/reject protected traffic safely.,Implemented,
   141,RKJYPB,If a CXL RP is not subject to GPC then CXL.cache must be disabled for it using an MSD-protected register.,Implemented,
   142,RPHWMM,A CXL Root Port that implements the RME-CDA DVSEC must comply with CXL-TSP.,Implemented,
   143,RJXPZP,CXL Root Ports map PAS and MECID to CXL TEE attributes and CKIDs correctly.,Implemented,
   144,RDWRKS,"With CDA TDISP enabled, CXL Root Port and host bridge security registers are RMSD write-protect.",Implemented,
   145,RWNPYD,A programming interface that allows read and write access to RNVS must be in the Root PAS.,Out of Scope,RNVS controls and reported properties are implementation-defined.
   146,RQCHPW,The system supports a method for permanently blocking write access from application PEs to all RNVS parameters.,Implemented,
   147,RLMSSL,The system supports a method for permanently blocking read access from application PEs to RNVS confidential parameters.,Out of Scope,RNVS controls and reported properties are implementation-defined.
   148,RVXBYG,System support for any memory protection property reported in System Properties is immutable and applicable for all DRAM memory controllers in the system.,Out of Scope,RNVS controls and reported properties are implementation-defined.
   149,RZHBBL,The memory-mapped registers of a Root watchdog are in the Root PAS.,Implemented,
   150,RVXGBP,A Root watchdog is capable of triggering an RME system reset when predefined expiration conditions are met.,Implemented,
   151,RQYRGG,MSD and RMSD are provided with a private interface for accessing a True Random Number Generator (TRNG) that meets the certification profile of the system.,Implemented,
   152,RNWQBJ,Tenant-hosted HES is isolated from other tenants in the Trusted subsystem.,Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   153,RHJSSG,The HES implementation exposes a private interface to SSD components such as Trusted subsystems for requesting HES services.,Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   154,RCGDVX,"The HES implementation exposes a programming interface in the Root PAS, shared by all application PEs, allowing MSD and PE Initial boot ROM to request for HES services.",Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   155,RBQPFG,HES has exclusive read and write access to RNVS confidential parameters.,Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   156,RBTWVY,"A measurement register can be either extended using a secure hash algorithm, locked or reset.",Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   157,RDFPJL,"HES has exclusive access to extend, lock, and reliably obtain the value of a measurement register it owns.",Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   158,RFWSRF,"Once locked, a measurement cannot be further extended until it is reset.",Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   159,RWYSLK,An RME system reset is the only method to reset a measurement owned by HES.,Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   160,RXCRMH,"On an RME system reset, HES state is reset to a known value, including all measurements and ephemeral cryptographic context.",Out of Scope,HES may be implemented in non-A-profile trusted hardware.
   161,RVDFYZ,A register that is located outside of the Root PAS but can affect a service provided by MSD must be implemented as a measurable register.,Out of Scope,Measurable-register selection is implementation-defined.
   162,RYLVDB,A measurable register is a write-lockable register that MSD has a trusted method to obtain its value.,Out of Scope,Measurable-register implementation is platform specific.
   163,RGNGMB,Only SSD or MSD are capable of controlling whether recording is performed for error records that might contain confidential information.,Out of Scope,RAS/error injection behavior is outside generic ACS scope.
   164,RGZTVL,Critical Error Interrupts (CI) must be wired to a Trusted subsystem that will respond with an RME system reset.,Out of Scope,RAS/error injection behavior is outside generic ACS scope.
   165,RLWVCX,An uncontainable error results in an RME system reset.,Out of Scope,RAS/error injection behavior is outside generic ACS scope.
   166,RJNBWJ,Only SSD or MSD can enable or disable Critical Error Interrupt generation.,Out of Scope,RAS/error injection behavior is outside generic ACS scope.
   167,RXPCTR,"Where an MPE provides support for integrity, if it detects an integrity error it can perform one of the following responses.",Out of Scope,RAS/error injection behavior is outside generic ACS scope.
   168,RHSVLQ,"Only SSD or MSD must be able to control the abilities of detecting, propagating, and reporting MPE integrity errors.",Out of Scope,RAS/error injection behavior is outside generic ACS scope.
   169,RGZHTD,MPEs pass poison information while preserving encryption and integrity behavior.,Out of Scope,RAS/error injection behavior is outside generic ACS scope.
   170,RRFSYB,RME systems propagate MPAM_SP to all relevant MSCs.,Out of Scope,MPAM MSC propagation is implementation/platform specific.
   171,RJYMQD,Allocation and protection of the address range assigned to an MTE carve-out are controlled by either SSD or MSD.,Implemented,
   172,RHRVJB,A system PMU counter that is accessible in the Secure PAS can only count events that are attributable to the Secure PAS or to the Non-secure PAS.,Out of Scope,System PMU events and per-PAS controls are implementation-defined.
   173,RBSZPN,A system PMU counter that is accessible in the Realm PAS can only count events that are attributable to the Realm PAS or to the Non-secure PAS.,Out of Scope,System PMU events and per-PAS controls are implementation-defined.
   174,RTMSNN,A system PMU counter that is accessible in the Root PAS can count events that are attributable to any PAS.,Out of Scope,System PMU events and per-PAS controls are implementation-defined.
   175,RMMPWY,Non-secure-accessible PMU counters need per-PAS authorization to count PAS-specific events.,Out of Scope,System PMU events and per-PAS controls are implementation-defined.
   176,RPLXZB,Per-PAS PMU authorization is driven by debug authentication or an appropriate PAS/Root register.,Out of Scope,System PMU events and per-PAS controls are implementation-defined.
   177,RCFYKS,An event that is not explicitly associated with a PAS but can leak confidential information is implicitly associated with the Root PAS.,Out of Scope,System PMU events and per-PAS controls are implementation-defined.
   178,RSQMWT,Application PEs in an RME system do not have architectural differences unless this is explicitly permitted by this specification.,Implemented,
   179,RCFYBJ,Implementation-defined PE differences must not weaken the RME security guarantee.,Out of Scope,Requires platform-specific review of implementation-defined PE properties.
   180,RXKBNZ,PE behavior is unpredictable when visible implementation differences are mismatched across PEs.,Out of Scope,UNPREDICTABLE mismatch conditions cannot be safely induced by generic ACS.
   181,RLRQXZ,"A software-initiated power state transition in an RME system at any level of the system hierarchy (PE, PE-cluster, System) is validated by MSD or by a Trusted subsystem.",Out of Scope,Power-transition validation is platform/firmware policy.
   182,RWJVRX,"Save/Restore operations for MSD PE context can only be done by MSD or a Trusted subsystem and use storage that is not accessible from Realm, Secure and Non-secure states.",Out of Scope,MSD PE context save/restore path is firmware/platform specific.
   183,RMVZHF,"Save/Restore operations for RMSD PE context can only be done by RMSD, MSD, or a Trusted subsystem and use storage that is not accessible from Secure and Non-secure states.",Out of Scope,RMSD PE context save/restore path is firmware/platform specific.
   184,RRCLYM,Secure PE context save/restore uses authorized agents and storage hidden from Realm and Non-secure states.,Out of Scope,Secure PE context save/restore path is firmware/platform specific.
   185,RGVJYZ,Power-policy or hardware-mode registers are MPRs or otherwise SSD-constrained.,Out of Scope,Power-policy registers are implementation-defined.
   186,RKYXMR,Any power management operation that can affect MSD state or the RME security guarantee must be validated by MSD or a Trusted subsystem.,Out of Scope,Power-management validation is platform/firmware policy.
   187,RMLJVR,"On an exit from a low power state in which system context is preserved, power control guarantees that MSD state is fully preserved.",Implemented,
   188,RZNLSZ,"Save/Restore operations for MSD state can only be done by MSD or a Trusted subsystem and use on-chip storage that is not accessible from Realm PAS, Secure PAS or Non-secure PAS.",Implemented,
   189,RDQTSG,An MPE or a PAS filter in a non-ACTIVE mode in which context is not fully retained blocks its operation and does not service requests until it is in ACTIVE mode again.,Implemented,
   190,RJDBCS,"An MMU-attached PAS filter in a non-ACTIVE mode either continues to respond to GPT cache invalidations, or invalidates any cached state when moving back to ACTIVE mode.",Implemented,
   191,RQSXBZ,RMSD external debugging and Root external debugging are disabled by default on a Secured Arm CCA system.,Out of Scope,External debug requires a common debugger/test interface unavailable to ACS.
   192,RHLTLK,RMSD external debugging can only be authorized following an RME system reset and before RMSD firmware is loaded and cannot change state until a subsequent RME system reset.,Out of Scope,External debug requires a common debugger/test interface unavailable to ACS.
   193,RXVNFV,Root external debugging can only be authorized following an RME system reset and before MSD firmware is loaded and cannot change state until a subsequent RME system reset.,Out of Scope,External debug requires a common debugger/test interface unavailable to ACS.
   194,RGTPGZ,"When Root external debugging is enabled, the RNVS confidential parameters are either inaccessible, scrubbed, or populated with debug values.",Out of Scope,External debug requires a common debugger/test interface unavailable to ACS.
   195,RRHGKX,"Access to a Secured Arm CCA system through an external debug or test interface, including debug access ports, JTAG ports, and scan interfaces is disabled by default.",Out of Scope,External debug requires a common debugger/test interface unavailable to ACS.
   196,RQLPNL,External debug power-up requests are permitted only through trusted power control.,Out of Scope,External debug requires a common debugger/test interface unavailable to ACS.
   197,RHJHRL,RME system reset resets Trusted requesters/subsystems and clears confidential state by trusted mechanisms.,Out of Scope,Full trusted-state reset coverage is platform specific.
   198,RKKSQB,"An RME system reset propagates to PEs as either a Cold reset, Warm reset, or Error recovery reset.",Implemented,
   199,RHLKZP,An RME system reset might propagate to any component that implements RAS [12] as an Error recovery reset.,Out of Scope,RAS error-recovery reset propagation is implementation-specific.
   200,RSSGMJ,"The reset of a system component that affects the RME security guarantee can only be controlled by MSD or a Trusted subsystem, or driven by an RME system reset.",Out of Scope,Security-affecting reset controls are implementation/platform specific.
   201,RKQLKN,LEGACY_TZ_EN is not permitted to change value after RME system reset has been deasserted.,Implemented,
   202,RKXMHF,"A system that contains RME components, that have the LEGACY_TZ_EN input, will drive a common tie-off input value into all components.",Implemented,
   203,RHCGZN,"If LEGACY_TZ_EN is TRUE, PAS[1] is driven to 0b0 by any logic that enforces Table",Implemented,
   204,RCLKXF,A PE that supports the LEGACY_TZ_EN tie-off hides the RME capability if LEGACY_TZ_EN is TRUE and reverts all functionality defined by RME.,Implemented,
   205,RCKBGZ,A legacy completer is attached to an RME IP by driving the NS signal of the completer from PAS[0] of the RME IP.,Out of Scope,Legacy requester/completer attachment is integration-specific.
   206,RYKSSD,A legacy requester is attached to an RME IP by driving PAS[0] of the RME IP from the NS signal of the legacy requester and driving PAS[1] of the RME IP to 0b0.,Out of Scope,Legacy requester/completer attachment is integration-specific.
   207,RLYXGC,"Multi-chip CTC interfaces transport PAS tags, MECIDs, CMOs, and DVM messages as required.",Out of Scope,Multi-chip CTC transport is platform specific.
   208,RHXJRC,"If an RME system supports 4 MPAM PARTID spaces, the CTC interface transports the MPAM_SP[1:0] indication.",Out of Scope,MPAM/CTC multi-chip signaling is implementation/platform specific.
   209,RGZMNH,An RME system reset in a multi-chip system affects all nodes.,Out of Scope,Multi-chip CTC reset behavior is platform specific.
   210,RCMMZS,Physically exposed CTC interfaces support cryptographic link encryption and integrity protection.,Out of Scope,CTC link protection needs platform/fabric visibility outside generic ACS.
   211,RVZCPW,CTC link protection provides IDE-equivalent or stronger encryption and integrity.,Out of Scope,CTC link-protection strength needs platform/fabric visibility outside generic ACS.
   212,RMSRGY,CTC link protection is mandatory for protected PAS transactions and PAS-independent traffic such as DVM messages.,Out of Scope,CTC link-protection coverage needs platform/fabric visibility outside generic ACS.
   213,RKYCPH,Security-sensitive CTC interface registers are MSD-protected or measurable.,Out of Scope,CTC security registers are implementation-defined or measurable-only.
   214,RLXPMB,Global multi-chip system state is established consistently across all nodes.,Out of Scope,Global multi-chip state establishment is platform specific.
   215,RFPYMV,"On a successful completion of an Arm TDISP VDM request, a corresponding response message is returned by the device.",Implemented,
   216,RWFPXR,The device is permitted to respond to any Arm TDISP VDM request with the TDISP_ERROR message as specified by TDISP [4].,Implemented,
   217,RPXLFY,GET_VERSION_REQ queries Arm TDISP VDM protocol versions supported by the device.,Implemented,
   218,RWFWLF,GET_VERSION_RESP returns the supported Arm TDISP VDM protocol version list.,Implemented,
   219,RXDKDT,SET_INTERFACE_REQ associates memory properties with a TDI.,Implemented,
   220,RFMHST,SET_INTERFACE_RESP returns the response header for SET_INTERFACE completion.,Implemented,
   221,RGRPDP,GET_DEV_PROP_REQ queries Arm TDISP VDM device properties.,Implemented,
   222,RGHDCB,GET_DEV_PROP_RESP returns Arm TDISP VDM device properties and register details.,Implemented,

.. checklist-table-end

