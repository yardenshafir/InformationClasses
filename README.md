# InformationClasses
Documenting system information classes and their uses

## System Information classes support in NtSet vs. NtQuery APIs:

| Information Class | NtSetSystemInformation  | NtQuerySystemInformation  | NtQuerySystemInformationEx | Supported | Allowed to restricted caller | Required privilege |
| ------- | --- | --- | --- | --- | --- | --- |
| SystemBasicInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemPerformanceInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemTimeOfDayInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemPathInformation | Invalid | Not implemented | Invalid | Yes | Yes | - |
| SystemProcessInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCallCountInformation | Invalid | Valid | Invalid | No | Yes | - |
| SystemDeviceInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorPerformanceInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemFlagsInformation | Valid | Valid | Invalid | Yes | Yes | SeDebugPrivilege + SeSystemtimePrivilege (set only) |
| SystemCallTimeInformation | Invalid | Not implemented | Invalid | Yes | Yes | - |
| SystemModuleInformation | Invalid | Valid | Invalid | Yes | No | - |
| SystemLocksInformation | Invalid | Valid | Invalid | Yes | No | - |
| SystemStackTraceInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemPagedPoolInformation | Invalid | Not implemented | Invalid | Yes | Yes | - |
| SystemNonPagedPoolInformation | Invalid | Not implemented | Invalid | Yes | Yes | - |
| SystemHandleInformation | Invalid | Valid | Invalid | Yes | No | - |
| SystemObjectInformation | Invalid | Valid | Invalid | Yes | No | - |
| SystemPageFileInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemVdmInstemulInformation | Invalid | Not implemented | Invalid | Yes | Yes | - |
| SystemVdmBopInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemFileCacheInformation | Valid | Valid | Invalid | Yes | Yes | SeIncreaseQuotaPrivilege |
| SystemPoolTagInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemInterruptInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemDpcBehaviorInformation | Valid | Valid | Invalid | Yes | Yes | SeLoadDriverPrivilege |
| SystemFullMemoryInformation | Invalid | Not implemented | Invalid | Yes | Yes | - |
| SystemLoadGdiDriverInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemUnloadGdiDriverInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemTimeAdjustmentInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemSummaryMemoryInformation | Invalid | Not implemented | Invalid | Yes | Yes | - |
| SystemMirrorMemoryInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemPerformanceTraceInformation | Not implemented | Not implemented | Invalid | Yes | Yes | - |
| SystemObsolete0 | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemExceptionInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCrashDumpStateInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemKernelDebuggerInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemContextSwitchInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemRegistryQuotaInformation | Valid | Valid | Invalid | Yes | Yes | SeIncreaseQuotaPrivilege |
| SystemExtendServiceTableInformation | Valid | Invalid | Invalid | Yes | Yes | SeLoadDriverPrivilege |
| SystemPrioritySeperation | Valid | Invalid | Invalid | Yes | Yes | SeTcbPrivilege |
| SystemVerifierAddDriverInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemVerifierRemoveDriverInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemProcessorIdleInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemLegacyDriverInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCurrentTimeZoneInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemLookasideInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemTimeSlipNotification | Valid | Invalid | Invalid | Yes | Yes | SeSystemtimePrivilege |
| SystemSessionCreate | Not implemented | Invalid | Invalid | Yes | Yes | - |
| SystemSessionDetach | Not implemented | Invalid | Invalid | Yes | Yes | - |
| SystemSessionInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemRangeStartInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemVerifierInformation | Valid | Valid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemVerifierThunkExtend | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemSessionProcessInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemLoadGdiDriverInSystemSpace | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemNumaProcessorMap | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemPrefetcherInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemExtendedProcessInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemRecommendedSharedDataAlignment | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemComPlusPackage | Valid | Valid | Invalid | Yes | Yes | - |
| SystemNumaAvailableMemory | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorPowerInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemEmulationBasicInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemEmulationProcessorInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemExtendedHandleInformation | Invalid | Valid | Invalid | Yes | No | - |
| SystemLostDelayedWriteInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemBigPoolInformation | Invalid | Valid | Invalid | Yes | No | - |
| SystemSessionPoolTagInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSessionMappedViewInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemHotpatchInformation | Valid | Valid | Invalid | No | Yes | - |
| SystemObjectSecurityMode | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemWatchdogTimerHandler | Valid | Invalid | Invalid | No | Yes | - |
| SystemWatchdogTimerInformation | Valid | Valid | Invalid | Yes | Yes | Kernel mode only (set only) |
| SystemLogicalProcessorInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemWow64SharedInformationObsolete | Not implemented | Invalid | Invalid | Yes | Yes | - |
| SystemRegisterFirmwareTableInformationHandler | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemFirmwareTableInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemModuleInformationEx | Invalid | Valid | Invalid | Yes | No | SeLoadDriverPrivilege |
| SystemVerifierTriageInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemSuperfetchInformation | Valid | Valid | Invalid | Yes | Yes | SeProfileSingleProcessPrivilege |
| SystemMemoryListInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemFileCacheInformationEx | Valid | Valid | Invalid | Yes | Yes | SeIncreaseQuotaPrivilege |
| SystemThreadPriorityClientIdInformation | Valid | Invalid | Invalid | Yes | Yes | SeIncreaseBasePriorityPrivilege |
| SystemProcessorIdleCycleTimeInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemVerifierCancellationInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemProcessorPowerInformationEx | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemRefTraceInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemSpecialPoolInformation | Valid | Valid | Invalid | Yes | Yes | SeDebugPrivilege (set only) |
| SystemProcessIdInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemErrorPortInformation | Valid | Invalid | Invalid | Yes | Yes | SeTcbPrivilege |
| SystemBootEnvironmentInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemHypervisorInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemVerifierInformationEx | Valid | Valid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemTimeZoneInformation | Valid | Invalid | Invalid | Yes | Yes | SeTimeZonePrivilege |
| SystemImageFileExecutionOptionsInformation | Valid | Invalid | Invalid | Yes | Yes | SeTcbPrivilege |
| SystemCoverageInformation | Valid | Valid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemPrefetchPatchInformation | Invalid | Not implemented | Invalid | Yes | Yes | SeProfileSingleProcessPrivilege |
| SystemVerifierFaultsInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemSystemPartitionInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSystemDiskInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorPerformanceDistribution | Invalid | Valid | Valid | Yes | Yes | - |
| SystemNumaProximityNodeInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemDynamicTimeZoneInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorMicrocodeUpdateInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemProcessorBrandString | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemVirtualAddressInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemLogicalProcessorAndGroupInformation | Invalid | Invalid | Valid | Yes | Yes | - |
| SystemProcessorCycleTimeInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemStoreInformation | Valid | Valid | Invalid | Yes | Yes | SeProfileSingleProcessPrivilege |
| SystemRegistryAppendString | Not implemented | Invalid | Invalid | Yes | Yes | - |
| SystemAitSamplingValue | Valid | Invalid | Invalid | Yes | Yes | SeProfileSingleProcessPrivilege |
| SystemVhdBootInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCpuQuotaInformation | Valid | Valid | Invalid | Yes | Yes | SeIncreaseQuotaPrivilege |
| SystemNativeBasicInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemErrorPortTimeouts | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemLowPriorityIoInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemBootEntropyInformation | Invalid | Valid | Invalid | Yes | Yes | Kernel mode only |
| SystemVerifierCountersInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemPagedPoolInformationEx | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSystemPtesInformationEx | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemNodeDistanceInformation | Invalid | Invalid | Valid | Yes | Yes | - |
| SystemAcpiAuditInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemBasicPerformanceInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemQueryPerformanceCounterInformation | Invalid | Valid | Invalid | No | Yes | - |
| SystemSessionBigPoolInformation | Invalid | Valid | Invalid | Yes | No | - |
| SystemBootGraphicsInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemScrubPhysicalMemoryInformation | Valid | Invalid | Invalid | Yes | Yes | SeProfileSingleProcessPrivilege |
| SystemBadPageInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorProfileControlArea | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemCombinePhysicalMemoryInformation | Valid | Invalid | Invalid | Yes | Yes | SeProfileSingleProcessPrivilege |
| SystemEntropyInterruptTimingInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemConsoleInformation | Valid | Invalid | Invalid | Yes | Yes | SeLoadDriverPrivilege |
| SystemPlatformBinaryInformation | Invalid | Valid | Invalid | Yes | Yes | SeTcbPrivilege |
| SystemPolicyInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemHypervisorProcessorCountInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemDeviceDataInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemDeviceDataEnumerationInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemMemoryTopologyInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemMemoryChannelInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemBootLogoInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorPerformanceInformationEx | Invalid | Valid | Valid | Yes | Yes | - |
| SystemCriticalProcessErrorLogInformation | Valid | Invalid | Invalid | Yes | Yes | SeShutdownPrivilege |
| SystemSecureBootPolicyInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemPageFileInformationEx | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSecureBootInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemEntropyInterruptTimingRawInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemPortableWorkspaceEfiLauncherInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemFullProcessInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemKernelDebuggerInformationEx | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemBootMetadataInformation | Valid | Valid | Invalid | Yes | Yes | SeTcbPrivilege |
| SystemSoftRebootInformation | Valid | Valid | Invalid | Yes | Yes | SeShutdownPrivilege |
| SystemElamCertificateInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemOfflineDumpConfigInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorFeaturesInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemRegistryReconciliationInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemEdidInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemManufacturingInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemEnergyEstimationConfigInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemHypervisorDetailInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorCycleStatsInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemVmGenerationCountInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemTrustedPlatformModuleInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemKernelDebuggerFlags | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityPolicyInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemIsolatedUserModeInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemHardwareSecurityTestInterfaceResultsInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSingleModuleInformation | Invalid | Valid | Invalid | Yes | Yes | Kernel mode only |
| SystemAllowedCpuSetsInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemVsmProtectionInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemInterruptCpuSetsInformation | Valid | Invalid | Invalid | Yes | Yes | SeIncreaseBasePriorityPrivilege |
| SystemSecureBootPolicyFullInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityPolicyFullInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemAffinitizedInterruptProcessorInformation | Invalid | Valid | Invalid | Yes | Yes | SeIncreaseBasePriorityPrivilege |
| SystemRootSiloInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCpuSetInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemCpuSetTagInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemWin32WerStartCallout | Valid | Invalid | Invalid | Yes | Yes | SeTcbPrivilege |
| SystemSecureKernelProfileInformation | Invalid | Valid | Valid | Yes | Yes | SeSystemProfilePrivilege |
| SystemCodeIntegrityPlatformManifestInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemInterruptSteeringInformation | Invalid | Invalid | Valid | Yes | Yes | - |
| SystemSupportedProcessorArchitectures | Invalid | Valid | Valid | Yes | Yes | - |
| SystemMemoryUsageInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityCertificateInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemPhysicalMemoryInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemControlFlowTransition | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemKernelDebuggingAllowed | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemActivityModerationExeState | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemActivityModerationUserSettings | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityPoliciesFullInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityUnlockInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemIntegrityQuotaInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemFlushInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemProcessorIdleMaskInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSecureDumpEncryptionInformation | Valid | Valid | Valid | Yes | Yes | SeDebugPrivilege (query), SeTcbPrivilege (set) |
| SystemWriteConstraintInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemKernelVaShadowInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemHypervisorSharedPageInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemFirmwareBootPerformanceInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityVerificationInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemFirmwarePartitionInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSpeculationControlInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemDmaGuardPolicyInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemEnclaveLaunchControlInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemWorkloadAllowedCpuSetsInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityUnlockModeInformation | Invalid | Invalid | Invalid | Yes | Yes | - |
| SystemLeapSecondInformation | Valid | Valid | Invalid | Yes | Yes | SeSystemtimePrivilege (set only) |
| SystemFlags2Information | Valid | Valid | Invalid | Yes | Yes | SeDebugPrivilege (set only) |
| SystemSecurityModelInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemCodeIntegritySyntheticCacheInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemFeatureConfigurationInformation | Valid | Invalid | Valid | Yes | Yes | - |
| SystemFeatureConfigurationSectionInformation | Invalid | Invalid | Valid | Yes | Yes | - |
| SystemFeatureUsageSubscriptionInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemSecureSpeculationControlInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemSpacesBootInformation | Invalid | Valid | Invalid | Yes | Yes | Kernel mode only |
| SystemFwRamdiskInformation | Invalid | Valid | Invalid | Yes | Yes | Kernel mode only |
| SystemWheaIpmiHardwareInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemDifSetRuleClassInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemDifClearRuleClassInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemDifApplyPluginVerificationOnDriver | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemDifRemovePluginVerificationOnDriver | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemShadowStackInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemBuildVersionInformation | Invalid | Invalid | Valid | Yes | Yes | - |
| SystemPoolLimitInformation | Valid | Invalid | Valid | Yes | Yes | SeIncreaseQuotaPrivilege |
| SystemCodeIntegrityAddDynamicStore | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemCodeIntegrityClearDynamicStores | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemDifPoolTrackingInformation | Valid | Invalid | Invalid | Yes | Yes | SeDebugPrivilege |
| SystemPoolZeroingInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemDpcWatchdogInformation | Valid | Valid | Invalid |peroff
| SystemDpcWatchdogInformation2 | Valid | Valid | Invalid | Yes | Yes | - |
| SystemSupportedProcessorArchitectures2 | Invalid | Valid | Valid | Yes | Yes | - |
| SystemSingleProcessorRelationshipInformation | Invalid | Invalid | Valid | Yes | Yes | - |
| SystemXfgCheckFailureInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemIommuStateInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemHypervisorMinrootInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemHypervisorBootPagesInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemPointerAuthInformation | Invalid | Valid | Invalid | No | Yes | - |
| SystemSecureKernelDebuggerInformation | Invalid | Valid | Invalid | No | Yes | - |

