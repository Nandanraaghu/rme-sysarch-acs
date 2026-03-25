/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#ifndef CXL_RGVRQC_HOST_PORT_COVERAGE_H
#define CXL_RGVRQC_HOST_PORT_COVERAGE_H

#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_cxl_spec.h"

pcie_cfgreg_bitfield_entry cxl_rgvrqc_bf_info_table[] = {
    /* Extended Capability Header ID */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_ECH_OFFSET,
        RP,
        0,
        15,
        RMECDA_ECH_ID,
        READ_ONLY,
        "ERROR CDA ECH_ID mismatch",
        "ERROR CDA ECH_ID attribute mismatch"
    },
    /* Extended Capability Version */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_ECH_OFFSET,
        RP,
        16,
        19,
        RMECDA_ECH_CAP_VER,
        READ_ONLY,
        "ERROR CDA capability version mismatch",
        "ERROR CDA capability version attribute mismatch"
    },
    /* DVSEC Header1 Vendor ID */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_HEAD1_OFFSET,
        RP,
        0,
        15,
        RMECDA_HEAD1_DVSEC_VID,
        READ_ONLY,
        "ERROR CDA DVSEC Vendor ID mismatch",
        "ERROR CDA DVSEC Vendor ID attribute mismatch"
    },
    /* DVSEC Header1 Revision */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_HEAD1_OFFSET,
        RP,
        16,
        19,
        RMECDA_HEAD1_DVSEC_REV,
        READ_ONLY,
        "ERROR CDA DVSEC revision mismatch",
        "ERROR CDA DVSEC revision attribute mismatch"
    },
        /* DVSEC Header1 Revision */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_HEAD1_OFFSET,
        RP,
        20,
        31,
        RMECDA_HEAD1_DVSEC_LENGTH,
        READ_ONLY,
        "ERROR CDA DVSEC length mismatch",
        "ERROR CDA DVSEC length attribute mismatch"
    },
    /* DVSEC Header2 ID */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_HEAD2_OFFSET,
        RP,
        0,
        15,
        RMECDA_HEAD2_DVSEC_ID,
        READ_ONLY,
        "ERROR CDA DVSEC ID mismatch",
        "ERROR CDA DVSEC ID attribute mismatch"
    },
    /* DVSEC Control1 reserved bits */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_CTL1_OFFSET,
        RP,
        2,
        15,
        0,
        RSVDP_RO,
        "ERROR CDA CTL1 reserved bits mismatch",
        "ERROR CDA CTL1 reserved attribute mismatch"
    },
     /* DVSEC Control1 reserved bits */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_CTL1_OFFSET,
        RP,
        29,
        31,
        0,
        RSVDP_RO,
        "ERROR CDA CTL1 reserved bits mismatch",
        "ERROR CDA CTL1 reserved attribute mismatch"
    },
    /* DVSEC Control3 reserved bits */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_CTL3_OFFSET,
        RP,
        0,
        7,
        0,
        RSVDP_RO,
        "ERROR CDA CTL3 reserved bits mismatch",
        "ERROR CDA CTL3 reserved attribute mismatch"
    },
    /* DVSEC Control3 reserved bits */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_CTL3_OFFSET,
        RP,
        24,
        31,
        0,
        RSVDP_RO,
        "ERROR CDA CTL3 reserved bits mismatch",
        "ERROR CDA CTL3 reserved attribute mismatch"
    },
    /* DVSEC Control4 reserved bits */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_CTL4_OFFSET,
        RP,
        1,
        7,
        0,
        RSVDP_RO,
        "ERROR CDA CTL4 reserved bits mismatch",
        "ERROR CDA CTL4 reserved attribute mismatch"
    },
    /* DVSEC Control4 reserved bits */
    {
        PCIE_ECAP,
        0,
        RMECDA_ECH_ID,
        RMECDA_CTL4_OFFSET,
        RP,
        24,
        31,
        0,
        RSVDP_RO,
        "ERROR CDA CTL4 reserved bits mismatch",
        "ERROR CDA CTL4 reserved attribute mismatch"
    },
};

#endif /* CXL_RGVRQC_HOST_PORT_COVERAGE_H */
