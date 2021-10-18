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
| SystemDpcWatchdogInformation | Valid | Valid | Invalid | Yes | Yes | - |
| SystemDpcWatchdogInformation2 | Valid | Valid | Invalid | Yes | Yes | - |
| SystemSupportedProcessorArchitectures2 | Invalid | Valid | Valid | Yes | Yes | - |
| SystemSingleProcessorRelationshipInformation | Invalid | Invalid | Valid | Yes | Yes | - |
| SystemXfgCheckFailureInformation | Invalid | Valid | Valid | Yes | Yes | - |
| SystemIommuStateInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemHypervisorMinrootInformation | Invalid | Valid | Invalid | Yes | Yes | - |
| SystemHypervisorBootPagesInformation | Valid | Invalid | Invalid | Yes | Yes | - |
| SystemPointerAuthInformation | Invalid | Valid | Invalid | No | Yes | - |
| SystemSecureKernelDebuggerInformation | Invalid | Valid | Invalid | No | Yes | - |

## Structures for Information Classes
Here are the structures for most of the system information classes. These were mostly gathered from public symbols and extracted using ntdiff, few were reverse engineered. Where there are embedded structures inside the one used by the API, these were included as well.
In some cases the class can be used for both NtSet and NtQuery APIs, then there are sometimes two separate structures for the two APIs.

### SystemBasicInformation + SystemNativeBasicInformation
Enum values: 0 + 114
```
typedef struct _SYSTEM_BASIC_INFORMATION
{
  ULONG Reserved;
  ULONG TimerResolution;
  ULONG PageSize;
  ULONG NumberOfPhysicalPages;
  ULONG LowestPhysicalPageNumber;
  ULONG HighestPhysicalPageNumber;
  ULONG AllocationGranularity;
  ULONG64 MinimumUserModeAddress;
  ULONG64 MaximumUserModeAddress;
  ULONG64 ActiveProcessorsAffinityMask;
  CHAR NumberOfProcessors;
  CHAR __PADDING__[7];
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;
```

### SystemProcessorInformation
Enum value: 1
```
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
  USHIRT ProcessorArchitecture;
  USHIRT ProcessorLevel;
  USHIRT ProcessorRevision;
  USHIRT MaximumProcessors;
  ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;
```

### SystemPerformanceInformation
Enum value: 2
```
typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
  LARGE_INTEGER IdleProcessTime;
  LARGE_INTEGER IoReadTransferCount;
  LARGE_INTEGER IoWriteTransferCount;
  LARGE_INTEGER IoOtherTransferCount;
  ULONG IoReadOperationCount;
  ULONG IoWriteOperationCount;
  ULONG IoOtherOperationCount;
  ULONG AvailablePages;
  ULONG CommittedPages;
  ULONG CommitLimit;
  ULONG PeakCommitment;
  ULONG PageFaultCount;
  ULONG CopyOnWriteCount;
  ULONG TransitionCount;
  ULONG CacheTransitionCount;
  ULONG DemandZeroCount;
  ULONG PageReadCount;
  ULONG PageReadIoCount;
  ULONG CacheReadCount;
  ULONG CacheIoCount;
  ULONG DirtyPagesWriteCount;
  ULONG DirtyWriteIoCount;
  ULONG MappedPagesWriteCount;
  ULONG MappedWriteIoCount;
  ULONG PagedPoolPages;
  ULONG NonPagedPoolPages;
  ULONG PagedPoolAllocs;
  ULONG PagedPoolFrees;
  ULONG NonPagedPoolAllocs;
  ULONG NonPagedPoolFrees;
  ULONG FreeSystemPtes;
  ULONG ResidentSystemCodePage;
  ULONG TotalSystemDriverPages;
  ULONG TotalSystemCodePages;
  ULONG NonPagedPoolLookasideHits;
  ULONG PagedPoolLookasideHits;
  ULONG AvailablePagedPoolPages;
  ULONG ResidentSystemCachePage;
  ULONG ResidentPagedPoolPage;
  ULONG ResidentSystemDriverPage;
  ULONG CcFastReadNoWait;
  ULONG CcFastReadWait;
  ULONG CcFastReadResourceMiss;
  ULONG CcFastReadNotPossible;
  ULONG CcFastMdlReadNoWait;
  ULONG CcFastMdlReadWait;
  ULONG CcFastMdlReadResourceMiss;
  ULONG CcFastMdlReadNotPossible;
  ULONG CcMapDataNoWait;
  ULONG CcMapDataWait;
  ULONG CcMapDataNoWaitMiss;
  ULONG CcMapDataWaitMiss;
  ULONG CcPinMappedDataCount;
  ULONG CcPinReadNoWait;
  ULONG CcPinReadWait;
  ULONG CcPinReadNoWaitMiss;
  ULONG CcPinReadWaitMiss;
  ULONG CcCopyReadNoWait;
  ULONG CcCopyReadWait;
  ULONG CcCopyReadNoWaitMiss;
  ULONG CcCopyReadWaitMiss;
  ULONG CcMdlReadNoWait;
  ULONG CcMdlReadWait;
  ULONG CcMdlReadNoWaitMiss;
  ULONG CcMdlReadWaitMiss;
  ULONG CcReadAheadIos;
  ULONG CcLazyWriteIos;
  ULONG CcLazyWritePages;
  ULONG CcDataFlushes;
  ULONG CcDataPages;
  ULONG ContextSwitches;
  ULONG FirstLevelTbFills;
  ULONG SecondLevelTbFills;
  ULONG SystemCalls;
  ULONG64 CcTotalDirtyPages;
  ULONG64 CcDirtyPageThreshold;
  ULONG64 ResidentAvailablePages;
  ULONG64 SharedCommittedPages;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;
```

### SystemTimeOfDayInformation
Enum value: 3
```
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
  LARGE_INTEGER BootTime;
  LARGE_INTEGER CurrentTime;
  LARGE_INTEGER TimeZoneBias;
  ULONG TimeZoneId;
  ULONG Reserved;
  ULONG64 BootTimeBias;
  ULONG64 SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;
```

### SystemProcessInformation
Enum value: 5
```
typedef struct _SYSTEM_PROCESS_INFORMATION
{
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER WorkingSetPrivateSize;
  ULONG HardFaultCount;
  ULONG NumberOfThreadsHighWatermark;
  ULONG64 CycleTime;
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  LONG BasePriority;
  PVOID UniqueProcessId;
  PVOID InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG64 UniqueProcessKey;
  ULONG64 PeakVirtualSize;
  ULONG64 VirtualSize;
  ULONG PageFaultCount;
  ULONG64 PeakWorkingSetSize;
  ULONG64 WorkingSetSize;
  ULONG64 QuotaPeakPagedPoolUsage;
  ULONG64 QuotaPagedPoolUsage;
  ULONG64 QuotaPeakNonPagedPoolUsage;
  ULONG64 QuotaNonPagedPoolUsage;
  ULONG64 PagefileUsage;
  ULONG64 PeakPagefileUsage;
  ULONG64 PrivatePageCount;
  LARGE_INTEGER ReadOperationCount;
  LARGE_INTEGER WriteOperationCount;
  LARGE_INTEGER OtherOperationCount;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION; 
```

### SystemCallCountInformation
Enum value: 6
```
typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
  ULONG Length;
  ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION; 
```

### SystemDeviceInformation
Enum value: 7
```
typedef struct _SYSTEM_DEVICE_INFORMATION
{
  ULONG NumberOfDisks;
  ULONG NumberOfFloppies;
  ULONG NumberOfCdRoms;
  ULONG NumberOfTapes;
  ULONG NumberOfSerialPorts;
  ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION; 
```

### SystemProcessorPerformanceInformation
Enum value: 8
```
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
  LARGE_INTEGER IdleTime;
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER DpcTime;
  LARGE_INTEGER InterruptTime;
  ULONG InterruptCount;
  LONG __PADDING__[1];
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION; 
```

### SystemFlagsInformation
Eunm value: 9
```
typedef struct _SYSTEM_FLAGS_INFORMATION
{
  ULONG Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION; 
```

### SystemCallTimeInformation
Enum value: 10
```
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
  ULONG Length;
  ULONG TotalCalls;
  LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION; 
```

### SystemModuleInformation
Enum value: 11
```
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
  PVOID Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION; 
```

### SystemLocksInformation
Enum value: 12
```
typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
  PVOID Address;
  USHORT Type;
  USHORT CreatorBackTraceIndex;
  PVOID OwningThread;
  LONG LockCount;
  ULONG ContentionCount;
  ULONG EntryCount;
  LONG RecursionCount;
  ULONG NumberOfWaitingShared;
  ULONG NumberOfWaitingExclusive;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION; 
```

### SystemStackTraceInformation
Enum value: 13
```
typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
{
  CHAR* SymbolicBackTrace;
  ULONG TraceCount;
  USHORT Index;
  USHORT Depth;
  PVOID BackTrace[32];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION; 

typedef struct _RTL_PROCESS_BACKTRACES
{
  ULONG64 CommittedMemory;
  ULONG64 ReservedMemory;
  ULONG NumberOfBackTraceLookups;
  ULONG NumberOfBackTraces;
  RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES; 
```

### SystemPagedPoolInformation + SystemNonPagedPoolInformation
Enum values: 14 + 15
```
typedef struct _SYSTEM_POOL_ENTRY
{
  CHAR Allocated;
  CHAR Spare0;
  USHORT AllocatorBackTraceIndex;
  ULONG Size;
  union
  {
    CHAR Tag[4];
    ULONG TagULONG;
    PVOID ProcessCHARgedQuota;
  }; 
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY; 

typedef struct _SYSTEM_POOL_INFORMATION
{
  ULONG64 TotalSize;
  PVOID FirstEntry;
  USHORT EntryOverhead;
  CHAR PoolTagPresent;
  CHAR Spare0;
  ULONG NumberOfEntries;
  SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION; 
```

### SystemHandleInformation
Enum value: 16
```
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
  USHORT UniqueProcessId;
  USHORT CreatorBackTraceIndex;
  CHAR ObjectTypeIndex;
  CHAR HandleAttributes;
  USHORT HandleValue;
  PVOID Object;
  ULONG GrantedAccess;
  LONG __PADDING__[1];
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO; 

typedef struct _SYSTEM_HANDLE_INFORMATION
{
  ULONG NumberOfHandles;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION; 
```

### SystemObjectInformation
Enum value: 17
```
typedef struct _SYSTEM_OBJECT_INFORMATION
{
  ULONG NextEntryOffset;
  PVOID Object;
  PVOID CreatorUniqueProcess;
  USHORT CreatorBackTraceIndex;
  USHORT Flags;
  LONG PointerCount;
  LONG HandleCount;
  ULONG PagedPoolCHARge;
  ULONG NonPagedPoolCHARge;
  PVOID ExclusiveProcessId;
  PVOID SecurityDescriptor;
  OBJECT_NAME_INFORMATION NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION; 
```

### SystemPageFileInformation
Enum value: 18
```
typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
  ULONG NextEntryOffset;
  ULONG TotalSize;
  ULONG TotalInUse;
  ULONG PeakUsage;
  UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION; 
```

### SystemFileCacheInformation
Enum value: 21
```
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
  ULONG64 CurrentSize;
  ULONG64 PeakSize;
  ULONG PageFaultCount;
  ULONG64 MinimumWorkingSet;
  ULONG64 MaximumWorkingSet;
  ULONG64 CurrentSizeIncludingTransitionInPages;
  ULONG64 PeakSizeIncludingTransitionInPages;
  ULONG TransitionRePurposeCount;
  ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION; 
```

### SystemPoolTagInformation
Enum value: 22
```
typedef struct _SYSTEM_POOLTAG
{
  union
  {
    CHAR Tag[4];
    ULONG TagULONG;
  }; 
  ULONG PagedAllocs;
  ULONG PagedFrees;
  ULONG64 PagedUsed;
  ULONG NonPagedAllocs;
  ULONG NonPagedFrees;
  ULONG64 NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG; 

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
  ULONG Count;
  SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION; 
```

### SystemInterruptInformation
Enum value: 23
```
typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
  ULONG ContextSwitches;
  ULONG DpcCount;
  ULONG DpcRate;
  ULONG TimeIncrement;
  ULONG DpcBypassCount;
  ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION; 
```

### SystemDpcBehaviorInformation
Enum value: 24
```
typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
  ULONG Spare;
  ULONG DpcQueueDepth;
  ULONG MinimumDpcRate;
  ULONG AdjustDpcThreshold;
  ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION; 
```

### SystemLoadGdiDriverInformation + SystemUnloadGdiDriverInformation + SystemLoadGdiDriverInSystemSpace
Enum values: 26 + 27 + 54
```
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
  UNICODE_STRING DriverName;
  PVOID ImageAddress;
  PVOID SectionPointer;
  PVOID EntryPoint;
  IMAGE_EXPORT_DIRECTORY* ExportSectionPointer;
  ULONG ImageLength;
  LONG __PADDING__[1];
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION; 
```

### SystemTimeAdjustmentInformation
Enum value: 28
```
typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
  ULONG TimeAdjustment;
  CHAR Enable;
  CHAR __PADDING__[3];
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION; 

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
  ULONG TimeAdjustment;
  ULONG TimeIncrement;
  CHAR Enable;
  CHAR __PADDING__[3];
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION; 
```

### SystemMirrorMemoryInformation
Enum value: 30

Requires no input buffer.

### SystemExceptionInformation
Enum value: 33
```
typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
  ULONG AlignmentFixupCount;
  ULONG ExceptionDispatchCount;
  ULONG FloatingEmulationCount;
  ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION; 
```

### SystemCrashDumpStateInformation
Enum value: 34
```
typedef enum _SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS
{
  SystemCrashDumpDisable = 0,
  SystemCrashDumpReconfigure = 1,
  SystemCrashDumpInitializationComplete = 2,
} SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS, *PSYSTEM_CRASH_DUMP_CONFIGURATION_CLASS;

typedef struct _SYSTEM_CRASH_DUMP_STATE_INFORMATION
{
  enum _SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS CrashDumpConfigurationClass;
} SYSTEM_CRASH_DUMP_STATE_INFORMATION, *PSYSTEM_CRASH_DUMP_STATE_INFORMATION; 
```

### SystemKernelDebuggerInformation
Enum value: 35
```
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
  CHAR KernelDebuggerEnabled;
  CHAR KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION; 
```

### SystemContextSwitchInformation
Enum value: 36
```
typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
  ULONG ContextSwitches;
  ULONG FindAny;
  ULONG FindLast;
  ULONG FindIdeal;
  ULONG IdleAny;
  ULONG IdleCurrent;
  ULONG IdleLast;
  ULONG IdleIdeal;
  ULONG PreemptAny;
  ULONG PreemptCurrent;
  ULONG PreemptLast;
  ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION; 
```

### SystemRegistryQuotaInformation
Enum value: 37
```
typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
  ULONG RegistryQuotaAllowed;
  ULONG RegistryQuotaUsed;
  ULONG64 PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION; 
```

### SystemExtendServiceTableInformation
Enum value: 38
```
typedef struct _SYSTEM_SERVICE_TABLE_EXTEND_INFORMATION
{
  UNICODE_STRING DriverName;
} SYSTEM_SERVICE_TABLE_EXTEND_INFORMATION, *PSYSTEM_SERVICE_TABLE_EXTEND_INFORMATION;
```

### SystemPrioritySeperation
Enum value: 39
```
typedef struct _SYSTEM_PRIORITY_SEPARATION_INFORMATION
{
  ULONG PrioritySeparation;
} SYSTEM_PRIORITY_SEPARATION_INFORMATION, *PSYSTEM_PRIORITY_SEPARATION_INFORMATION;
```

### SystemVerifierAddDriverInformation + SystemVerifierRemoveDriverInformation
Enum values: 40 + 41
```
typedef struct _SYSTEM_VERIFIER_DRIVER_INFORMATION
{
  UNICODE_STRING DriverName;
} SYSTEM_VERIFIER_DRIVER_INFORMATION, *PSYSTEM_VERIFIER_DRIVER_INFORMATION;
```

### SystemProcessorIdleInformation
Enum value: 42
```
typedef struct _SYSTEM_PROCESSOR_IDLE_INFORMATION
{
  ULONG64 IdleTime;
  ULONG64 C1Time;
  ULONG64 C2Time;
  ULONG64 C3Time;
  ULONG C1Transitions;
  ULONG C2Transitions;
  ULONG C3Transitions;
  ULONG Padding;
} SYSTEM_PROCESSOR_IDLE_INFORMATION, *PSYSTEM_PROCESSOR_IDLE_INFORMATION; 
```

### SystemLegacyDriverInformation
Enum value: 43
```
typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
  ULONG VetoType;
  UNICODE_STRING VetoList;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION; 
```

### SystemCurrentTimeZoneInformation
Enum value: 44
```
typedef struct _RTL_TIME_ZONE_INFORMATION
{
  LONG Bias;
  wCHAR_t StandardName[32];
  TIME_FIELDS StandardStart;
  LONG StandardBias;
  wCHAR_t DaylightName[32];
  TIME_FIELDS DaylightStart;
  LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION; 
```

### SystemLookasideInformation
Enum value: 45
```
typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
  USHORT CurrentDepth;
  USHORT MaximumDepth;
  ULONG TotalAllocates;
  ULONG AllocateMisses;
  ULONG TotalFrees;
  ULONG FreeMisses;
  ULONG Type;
  ULONG Tag;
  ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION; 
```

### SystemTimeSlipNotification
Enum value: 46
```
typedef struct _SYSTEM_TIME_SLIP_NOTIFICATION_INFORMATION
{
  HANDLE EventHandle;
} SYSTEM_TIME_SLIP_NOTIFICATION_INFORMATION, *PSYSTEM_TIME_SLIP_NOTIFICATION_INFORMATION;
```

### SystemRangeStartInformation
Enum value: 50
```
typedef struct _SYSTEM_RANGE_START_INFORMATION
{
  PVOID RangeStartAddress;
} SYSTEM_RANGE_START_INFORMATION, *PSYSTEM_RANGE_START_INFORMATION;
```

### SystemVerifierInformation
Enum value: 51
```
typedef struct _SYSTEM_VERIFIER_INFORMATION
{
  ULONG NextEntryOffset;
  ULONG Level;
  ULONG RuleClasses[2];
  ULONG TriageContext;
  union
  {
    union
    {
      struct
      {
        struct 
        {
          ULONG AreAllDriversBeingVerified : 1; 
          ULONG DisabledFromCrash : 1; 
          ULONG Spare : 30; 
        }; 
      } Flags;
      ULONG Whole;
    }; 
  } u1;
  UNICODE_STRING DriverName;
  ULONG RaiseIrqls;
  ULONG AcquireSpinLocks;
  ULONG SynchronizeExecutions;
  ULONG AllocationsAttempted;
  ULONG AllocationsSucceeded;
  ULONG AllocationsSucceededSpecialPool;
  ULONG AllocationsWithNoTag;
  ULONG TrimRequests;
  ULONG Trims;
  ULONG AllocationsFailed;
  ULONG AllocationsFailedDeliberately;
  ULONG Loads;
  ULONG Unloads;
  ULONG UnTrackedPool;
  ULONG CurrentPagedPoolAllocations;
  ULONG CurrentNonPagedPoolAllocations;
  ULONG PeakPagedPoolAllocations;
  ULONG PeakNonPagedPoolAllocations;
  ULONG64 PagedPoolUsageInBytes;
  ULONG64 NonPagedPoolUsageInBytes;
  ULONG64 PeakPagedPoolUsageInBytes;
  ULONG64 PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION; 
```

### SystemVerifierThunkExtend
Enum value: 52

Receives an array of DRIVER_VERIFIER_THUNK_PAIRS:
```
typedef struct _DRIVER_VERIFIER_THUNK_PAIRS
{
  PVOID PristineRoutine ;
  PVOID NewRoutine ;
} DRIVER_VERIFIER_THUNK_PAIRS, *PDRIVER_VERIFIER_THUNK_PAIRS; 
```

### SystemSessionProcessInformation
Enum value: 53
```
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
  ULONG SessionId;
  ULONG SizeOfBuf;
  PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION; 
```

### SystemNumaProcessorMap
Enum value: 55
```
typedef struct _SYSTEM_NUMA_INFORMATION
{
  ULONG HighestNodeNumber;
  ULONG Reserved;
  union
  {
    GROUP_AFFINITY ActiveProcessorsGroupAffinity[64];
    ULONG64 AvailableMemory[64];
    ULONG64 Pad[128];
  }; 
} SYSTEM_NUMA_INFORMATION, *PSYSTEM_NUMA_INFORMATION; 
```

### SystemPrefetcherInformation
Enum value: 56
```
typedef struct _SYSTEM_PREFETCH_INFORMATION
{
  ULONG Version;
  ULONG Signature;
  ULONG Flags;
  ULONG Unknown;
  ULONG BootPhase;
  ULONG BufferSize;
  ULONG Flags2;
  ULONG Pad[4];
} SYSTEM_PREFETCH_INFORMATION, *PSYSTEM_PREFETCH_INFORMATION;
```

### SystemExtendedProcessInformation
Enum value: 57

Returns a buffer containing a SYSTEM_PROCESS_INFORMATION structure followed by SYSTEM_PROCESS_INFORMATION_EXTENSION:
```
typedef struct _SYSTEM_PROCESS_INFORMATION_EXTENSION
{
  PROCESS_DISK_COUNTERS DiskCounters;
  ULONG64 ContextSwitches;
  union
  {
    ULONG Flags;
    struct 
    {
      ULONG HasStrongId : 1; 
      ULONG Classification : 4; 
      ULONG BackgroundActivityModerated : 1; 
      ULONG Spare : 26; 
    }; 
  }; 
  ULONG UserSidOffset;
  ULONG PackageFullNameOffset;
  PROCESS_ENERGY_VALUES EnergyValues;
  ULONG AppIdOffset;
  ULONG64 SharedCommitCHARge;
  ULONG JobObjectId;
  ULONG SpareULONG;
  ULONG64 ProcessSequenceNumber;
} SYSTEM_PROCESS_INFORMATION_EXTENSION, *PSYSTEM_PROCESS_INFORMATION_EXTENSION; 
```

### SystemRecommendedSharedDataAlignment
Enum value: 58
```
typedef struct _SYSTEM_RECOMMENDED_ALIGNMENT_INFORMATION
{
  ULONG RecommendedAlignment;
} SYSTEM_RECOMMENDED_ALIGNMENT_INFORMATION, *PSYSTEM_RECOMMENDED_ALIGNMENT_INFORMATION;
```

### SystemComPlusPackage
Enum value: 59
```
typedef struct _SYSTEM_PACKAGE_INFORMATION
{
  ULONG Value;
} SYSTEM_PACKAGE_INFORMATION, *PSYSTEM_PACKAGE_INFORMATION;
```

### SystemNumaAvailableMemory
Enum value: 60
```
typedef struct _SYSTEM_NUMA_INFORMATION
{
  ULONG HighestNodeNumber;
  ULONG Reserved;
  union
  {
    GROUP_AFFINITY ActiveProcessorsGroupAffinity[64];
    ULONG64 AvailableMemory[64];
    ULONG64 Pad[128];
  }; 
} SYSTEM_NUMA_INFORMATION, *PSYSTEM_NUMA_INFORMATION; 
```

### SystemProcessorPowerInformation
Enum value: 61
```
typedef struct _SYSTEM_PROCESSOR_POWER_INFORMATION
{
  CHAR CurrentFrequency;
  CHAR ThermalLimitFrequency;
  CHAR ConstantThrottleFrequency;
  CHAR DegradedThrottleFrequency;
  CHAR LastBusyFrequency;
  CHAR LastC3Frequency;
  CHAR LastAdjustedBusyFrequency;
  CHAR ProcessorMinThrottle;
  CHAR ProcessorMaxThrottle;
  ULONG NumberOfFrequencies;
  ULONG PromotionCount;
  ULONG DemotionCount;
  ULONG ErrorCount;
  ULONG RetryCount;
  ULONG64 CurrentFrequencyTime;
  ULONG64 CurrentProcessorTime;
  ULONG64 CurrentProcessorIdleTime;
  ULONG64 LastProcessorTime;
  ULONG64 LastProcessorIdleTime;
  ULONG64 Energy;
} SYSTEM_PROCESSOR_POWER_INFORMATION, *PSYSTEM_PROCESSOR_POWER_INFORMATION; 
```

### SystemEmulationBasicInformation
Enum value: 62
```
typedef struct _SYSTEM_BASIC_INFORMATION
{
  ULONG Reserved;
  ULONG TimerResolution;
  ULONG PageSize;
  ULONG NumberOfPhysicalPages;
  ULONG LowestPhysicalPageNumber;
  ULONG HighestPhysicalPageNumber;
  ULONG AllocationGranularity;
  ULONG64 MinimumUserModeAddress;
  ULONG64 MaximumUserModeAddress;
  ULONG64 ActiveProcessorsAffinityMask;
  CHAR NumberOfProcessors;
  CHAR __PADDING__[7];
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION; 
```

### SystemEmulationProcessorInformation
Enum value: 63
```
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
  USHORT ProcessorArchitecture;
  USHORT ProcessorLevel;
  USHORT ProcessorRevision;
  USHORT MaximumProcessors;
  ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION; 
```

### SystemExtendedHandleInformation
Enum value: 64
```
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
  ULONG64 NumberOfHandles;
  ULONG64 Reserved;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
```

### SystemLostDelayedWriteInformation
Enum value: 65
```
typedef struct _SYSTEM_LOST_DELAYED_WRITES_INFORMATION
{
  ULONG LostDelayedWrites;
} SYSTEM_LOST_DELAYED_WRITES_INFORMATION, *PSYSTEM_LOST_DELAYED_WRITES_INFORMATION;
```

### SystemBigPoolInformation
Enum value: 66
```
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
  union
  {
    PVOID VirtualAddress;
    ULONG64 NonPaged : 1; 
  }; 
  ULONG64 SizeInBytes;
  union
  {
    CHAR Tag[4];
    ULONG TagULONG;
  }; 
  LONG __PADDING__[1];
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY; 

typedef struct _SYSTEM_SESSION_BIGPOOL_INFORMATION
{
  ULONG64 NextEntryOffset;
  ULONG SessionId;
  ULONG Count;
  SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_SESSION_BIGPOOL_INFORMATION, *PSYSTEM_SESSION_BIGPOOL_INFORMATION; 
```

### SystemSessionPoolTagInformation
Enum value: 67
```
typedef struct _SYSTEM_POOLTAG
{
  union
  {
    CHAR Tag[4];
    ULONG TagULONG;
  }; 
  ULONG PagedAllocs;
  ULONG PagedFrees;
  ULONG64 PagedUsed;
  ULONG NonPagedAllocs;
  ULONG NonPagedFrees;
  ULONG64 NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG; 

typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION
{
  ULONG64 NextEntryOffset;
  ULONG SessionId;
  ULONG Count;
  SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_SESSION_POOLTAG_INFORMATION, *PSYSTEM_SESSION_POOLTAG_INFORMATION; 
```

### SystemSessionMappedViewInformation
Enum value: 68
```
typedef struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
{
  ULONG64 NextEntryOffset;
  ULONG SessionId;
  ULONG ViewFailures;
  ULONG64 NumberOfBytesAvailable;
  ULONG64 NumberOfBytesAvailableContiguous;
} SYSTEM_SESSION_MAPPED_VIEW_INFORMATION, *PSYSTEM_SESSION_MAPPED_VIEW_INFORMATION; 
```

### SystemObjectSecurityMode
Enum value: 70
```
typedef struct _SYSTEM_OBJECT_SECURITY_MODE_INFORMATION
{
  ULONG ObjectSecurityMode;
} SYSTEM_OBJECT_SECURITY_MODE_INFORMATION, *PSYSTEM_OBJECT_SECURITY_MODE_INFORMATION;
```

### SystemWatchdogTimerInformation
Enum value: 72
```
typedef enum _WATCHDOG_INFORMATION_CLASS
{
  WdInfoTimeoutValue = 0,
  WdInfoResetTimer = 1,
  WdInfoStopTimer = 2,
  WdInfoStartTimer = 3,
  WdInfoTriggerAction = 4,
  WdInfoState = 5,
  WdInfoTriggerReset = 6,
  WdInfoNop = 7,
  WdInfoGeneratedLastReset = 8,
  WdInfoInvalid = 9,
} WATCHDOG_INFORMATION_CLASS, *PWATCHDOG_INFORMATION_CLASS;

typedef struct _SYSTEM_WATCHDOG_TIMER_INFORMATION
{
  enum _WATCHDOG_INFORMATION_CLASS WdInfoClass;
  ULONG DataValue;
} SYSTEM_WATCHDOG_TIMER_INFORMATION, *PSYSTEM_WATCHDOG_TIMER_INFORMATION; 
```

### SystemLogicalProcessorInformation
Enum value: 73
```
typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP
{
  RelationProcessorCore = 0,
  RelationNumaNode = 1,
  RelationCache = 2,
  RelationProcessorPackage = 3,
  RelationGroup = 4,
  RelationProcessorDie = 5,
  RelationNumaNodeEx = 6,
  RelationProcessorModule = 7,
  RelationAll = 0xffffffff,
} LOGICAL_PROCESSOR_RELATIONSHIP, *PLOGICAL_PROCESSOR_RELATIONSHIP;

typedef enum _PROCESSOR_CACHE_TYPE
{
  CacheUnified = 0,
  CacheInstruction = 1,
  CacheData = 2,
  CacheTrace = 3,
} PROCESSOR_CACHE_TYPE, *PPROCESSOR_CACHE_TYPE;

typedef struct _CACHE_DESCRIPTOR
{
  CHAR Level;
  CHAR Associativity;
  USHORT LineSize;
  ULONG Size;
  enum _PROCESSOR_CACHE_TYPE Type;
} CACHE_DESCRIPTOR, *PCACHE_DESCRIPTOR; 

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION
{
  ULONG64 ProcessorMask;
  enum _LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
  union
  {
    struct
    {
      CHAR Flags;
    } ProcessorCore;
    struct
    {
      ULONG NodeNumber;
    } NumaNode;
    CACHE_DESCRIPTOR Cache;
    ULONG64 Reserved[2];
  }; 
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION; 
```

### SystemRegisterFirmwareTableInformationHandler
Enum value: 75
```
typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
  ULONG ProviderSignature;
  CHAR Register;
  PVOID FirmwareTableHandler ;
  PVOID DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER, *PSYSTEM_FIRMWARE_TABLE_HANDLER; 
```

### SystemFirmwareTableInformation
Enum value: 76
```
typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
  SystemFirmwareTable_Enumerate = 0,
  SystemFirmwareTable_Get = 1,
} SYSTEM_FIRMWARE_TABLE_ACTION, *PSYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
  ULONG ProviderSignature;
  enum _SYSTEM_FIRMWARE_TABLE_ACTION Action;
  ULONG TableID;
  ULONG TableBufferLength;
  CHAR TableBuffer[1];
  CHAR __PADDING__[3];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION; 
```

### SystemModuleInformationEx
Enum value: 77
```
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
  USHORT NextOffset;
  RTL_PROCESS_MODULE_INFORMATION BaseInfo;
  ULONG ImageChecksum;
  ULONG TimeDateStamp;
  PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX; 
```

### SystemVerifierTriageInformation
Enum value: 78
```
typedef struct _SYSTEM_VERIFIER_TRIAGE_INFORMATION
{
  ULONG ActionTaken;
  ULONG64 CrashData[5];
  ULONG VerifierMode;
  ULONG VerifierFlags;
  wCHAR_t VerifierTargets[256];
} SYSTEM_VERIFIER_TRIAGE_INFORMATION, *PSYSTEM_VERIFIER_TRIAGE_INFORMATION; 
```

### SystemSuperfetchInformation
Enum value: 79
```
typedef struct _SYSTEM_PREFETCH_INFORMATION
{
  ULONG Version;
  ULONG Signature;
  ULONG Flags;
  ULONG Unknown;
  ULONG BootPhase;
  ULONG BufferSize;
  ULONG Flags2;
  ULONG Pad[4];
} SYSTEM_PREFETCH_INFORMATION, *PSYSTEM_PREFETCH_INFORMATION;
```

### SystemMemoryListInformation
Enum value: 80
```
typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
  ULONG64 ZeroPageCount;
  ULONG64 FreePageCount;
  ULONG64 ModifiedPageCount;
  ULONG64 ModifiedNoWritePageCount;
  ULONG64 BadPageCount;
  ULONG64 PageCountByPriority[8];
  ULONG64 RepurposedPagesByPriority[8];
  ULONG64 ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION, *PSYSTEM_MEMORY_LIST_INFORMATION; 
```

### SystemFileCacheInformationEx
Enum value: 81
```
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
  ULONG64 CurrentSize;
  ULONG64 PeakSize;
  ULONG PageFaultCount;
  ULONG64 MinimumWorkingSet;
  ULONG64 MaximumWorkingSet;
  ULONG64 CurrentSizeIncludingTransitionInPages;
  ULONG64 PeakSizeIncludingTransitionInPages;
  ULONG TransitionRePurposeCount;
  ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION; 
```

### SystemThreadPriorityClientIdInformation
Enum value: 82
```
typedef struct _SYSTEM_THREAD_CID_PRIORITY_INFORMATION
{
  CLIENT_ID ClientId;
  LONG Priority;
  LONG __PADDING__[1];
} SYSTEM_THREAD_CID_PRIORITY_INFORMATION, *PSYSTEM_THREAD_CID_PRIORITY_INFORMATION; 
```

### SystemProcessorIdleCycleTimeInformation
Enum value: 83
```
typedef struct _SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION
{
  ULONG64 CycleTime;
} SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION, *PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION; 
```

### SystemVerifierCancellationInformation
Enum value: 84
```
typedef struct _SYSTEM_VERIFIER_ISSUE
{
  ULONG64 IssueType;
  PVOID Address;
  ULONG64 Parameters[2];
} SYSTEM_VERIFIER_ISSUE, *PSYSTEM_VERIFIER_ISSUE; 

typedef struct _SYSTEM_VERIFIER_CANCELLATION_INFORMATION
{
  ULONG CancelProbability;
  ULONG CancelThreshold;
  ULONG CompletionThreshold;
  ULONG CancellationVerifierDisabled;
  ULONG AvailableIssues;
  SYSTEM_VERIFIER_ISSUE Issues[128];
} SYSTEM_VERIFIER_CANCELLATION_INFORMATION, *PSYSTEM_VERIFIER_CANCELLATION_INFORMATION; 
```

### SystemRefTraceInformation
Enum value: 86
```
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
  CHAR TraceEnable;
  CHAR TracePermanent;
  UNICODE_STRING TraceProcessName;
  UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION; 
```

### SystemSpecialPoolInformation
Enum value: 87
```
typedef struct _SYSTEM_SPECIAL_POOL_INFORMATION
{
  ULONG PoolTag;
  ULONG Flags;
} SYSTEM_SPECIAL_POOL_INFORMATION, *PSYSTEM_SPECIAL_POOL_INFORMATION; 
```

### SystemProcessIdInformation
Enum value: 88
```
typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
  PVOID ProcessId;
  UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION; 
```

### SystemBootEnvironmentInformation
Enum value: 90
```
typedef enum _FIRMWARE_TYPE
{
  FirmwareTypeUnknown = 0,
  FirmwareTypeBios = 1,
  FirmwareTypeUefi = 2,
  FirmwareTypeMax = 3,
} FIRMWARE_TYPE, *PFIRMWARE_TYPE;

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
  GUID BootIdentifier;
  enum _FIRMWARE_TYPE FirmwareType;
  union
  {
    ULONG64 BootFlags;
    struct 
    {
      ULONG64 DbgMenuOsSelection : 1; 
      ULONG64 DbgHiberBoot : 1; 
      ULONG64 DbgSoftBoot : 1; 
      ULONG64 DbgMeasuredLaunch : 1; 
      ULONG64 DbgMeasuredLaunchCapable : 1; 
      ULONG64 DbgSystemHiveReplace : 1; 
      ULONG64 DbgMeasuredLaunchSmmProtections : 1; 
      ULONG64 DbgMeasuredLaunchSmmLevel : 7; 
    }; 
  }; 
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION; 
```

### SystemHypervisorInformation
Enum value: 91
```
typedef struct _SYSTEM_HYPERVISOR_QUERY_INFORMATION
{
  CHAR HypervisorConnected;
  CHAR HypervisorDebuggingEnabled;
  CHAR HypervisorPresent;
  CHAR HypervisorSchedulerType;
  CHAR Spare0[4];
  ULONG64 EnabledEnlightenments;
} SYSTEM_HYPERVISOR_QUERY_INFORMATION, *PSYSTEM_HYPERVISOR_QUERY_INFORMATION; 
```

### SystemVerifierInformationEx
Enum value: 92
```
typedef struct _SYSTEM_VERIFIER_INFORMATION_EX
{
  ULONG VerifyMode;
  ULONG OptionChanges;
  UNICODE_STRING PreviousBucketName;
  ULONG IrpCancelTimeoutMsec;
  ULONG VerifierExtensionEnabled;
  ULONG Reserved[1];
  LONG __PADDING__[1];
} SYSTEM_VERIFIER_INFORMATION_EX, *PSYSTEM_VERIFIER_INFORMATION_EX; 
```

### SystemTimeZoneInformation
Enum value: 93
```
typedef struct _RTL_TIME_ZONE_INFORMATION
{
  LONG Bias;
  wCHAR_t StandardName[32];
  TIME_FIELDS StandardStart;
  LONG StandardBias;
  wCHAR_t DaylightName[32];
  TIME_FIELDS DaylightStart;
  LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION; 
```

### SystemImageFileExecutionOptionsInformation
Enum value: 94
```
typedef struct _SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION
{
  ULONG FlagsToEnable;
  ULONG FlagsToDisable;
} SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION, *PSYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION; 
```

### SystemCoverageInformation
Enum value: 95
```
typedef struct _COVERAGE_MODULES
{
  ULONG ListAndReset;
  ULONG NumberOfModules;
  COVERAGE_MODULE_REQUEST ModuleRequestInfo;
  COVERAGE_MODULE_INFO Modules[1];
} COVERAGE_MODULES, *PCOVERAGE_MODULES; 
```

### SystemPrefetchPatchInformation
Enum value: 96
```
typedef struct _SYSTEM_PREFETCH_PATCH_INFORMATION
{
  ULONG PrefetchPatchCount;
} SYSTEM_PREFETCH_PATCH_INFORMATION, *PSYSTEM_PREFETCH_PATCH_INFORMATION; 
```

### SystemVerifierFaultsInformation
Enum value: 97
```
typedef struct _SYSTEM_VERIFIER_FAULTS_INFORMATION
{
  ULONG Probability;
  ULONG MaxProbability;
  UNICODE_STRING PoolTags;
  UNICODE_STRING Applications;
} SYSTEM_VERIFIER_FAULTS_INFORMATION, *PSYSTEM_VERIFIER_FAULTS_INFORMATION; 
```

### SystemSystemPartitionInformation
Enum value: 98
```
typedef struct _SYSTEM_SYSTEM_PARTITION_INFORMATION
{
  UNICODE_STRING SystemPartition;
} SYSTEM_SYSTEM_PARTITION_INFORMATION, *PSYSTEM_SYSTEM_PARTITION_INFORMATION; 
```

### SystemSystemDiskInformation
Enum value: 99
```
typedef struct _SYSTEM_SYSTEM_DISK_INFORMATION
{
  UNICODE_STRING SystemDisk;
} SYSTEM_SYSTEM_DISK_INFORMATION, *PSYSTEM_SYSTEM_DISK_INFORMATION; 
```

### SystemProcessorPerformanceDistribution
Enum value: 100
```
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
{
  ULONG ProcessorCount;
  ULONG Offsets[1];
} SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION, *PSYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION; 
```

### SystemNumaProximityNodeInformation
Enum value: 101
```
typedef struct _SYSTEM_NUMA_PROXIMITY_MAP
{
  ULONG NodeProximityId;
  USHORT NodeNumber;
  CHAR __PADDING__[2];
} SYSTEM_NUMA_PROXIMITY_MAP, *PSYSTEM_NUMA_PROXIMITY_MAP; 
```

### SystemDynamicTimeZoneInformation
Enum value: 102
```
typedef struct _TIME_DYNAMIC_ZONE_INFORMATION
{
  LONG Bias;
  wCHAR_t StandardName[32];
  SYSTEMTIME StandardDate;
  LONG StandardBias;
  wCHAR_t DaylightName[32];
  SYSTEMTIME DaylightDate;
  LONG DaylightBias;
  wCHAR_t TimeZoneKeyName[128];
  CHAR DynamicDaylightTimeDisabled;
  CHAR __PADDING__[3];
} TIME_DYNAMIC_ZONE_INFORMATION, *PTIME_DYNAMIC_ZONE_INFORMATION; 
```

### SystemCodeIntegrityInformation
Enum value: 103
```
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
  ULONG Length;
  ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION; 
```

### SystemProcessorMicrocodeUpdateInformation
Enum value: 104
```
typedef struct _SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
{
  ULONG Operation;
} SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION, *PSYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION; 
```

### SystemLogicalProcessorAndGroupInformation
Enum value: 107
```
typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
{
  enum _LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
  ULONG Size;
  union
  {
    PROCESSOR_RELATIONSHIP Processor;
    NUMA_NODE_RELATIONSHIP NumaNode;
    CACHE_RELATIONSHIP Cache;
    GROUP_RELATIONSHIP Group;
  }; 
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX; 
```

### SystemProcessorCycleTimeInformation
Enum value: 108
```
typedef struct _SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION
{
  ULONG64 CycleTime;
} SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION, *PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION; 
```

### SystemVhdBootInformation
Enum value: 112
```
typedef struct _SYSTEM_VHD_BOOT_INFORMATION
{
  CHAR OsDiskIsVhd;
  ULONG OsVhdFilePathOffset;
  wCHAR_t OsVhdParentVolume[1];
  CHAR __PADDING__[2];
} SYSTEM_VHD_BOOT_INFORMATION, *PSYSTEM_VHD_BOOT_INFORMATION; 
```

### SystemCpuQuotaInformation
Enum value: 113
```
typedef struct _PS_CPU_QUOTA_QUERY_ENTRY
{
  ULONG SessionId;
  ULONG Weight;
} PS_CPU_QUOTA_QUERY_ENTRY, *PPS_CPU_QUOTA_QUERY_ENTRY; 

typedef struct _PS_CPU_QUOTA_QUERY_INFORMATION
{
  ULONG SessionCount;
  PS_CPU_QUOTA_QUERY_ENTRY SessionInformation[1];
} PS_CPU_QUOTA_QUERY_INFORMATION, *PPS_CPU_QUOTA_QUERY_INFORMATION; 

typedef struct _PS_CPU_QUOTA_SET_INFORMATION
{
  __int64 SessionHandle;
  ULONG Weight;
  LONG __PADDING__[1];
} PS_CPU_QUOTA_SET_INFORMATION, *PPS_CPU_QUOTA_SET_INFORMATION; 
```

### SystemErrorPortTimeouts
Enum value: 115
```
typedef struct _SYSTEM_ERROR_PORT_TIMEOUTS
{
  ULONG StartTimeout;
  ULONG CommTimeout;
} SYSTEM_ERROR_PORT_TIMEOUTS, *PSYSTEM_ERROR_PORT_TIMEOUTS; 
```

### SystemLowPriorityIoInformation
Enum value: 116
```
typedef struct _SYSTEM_LOW_PRIORITY_IO_INFORMATION
{
  ULONG LowPriReadOperations;
  ULONG LowPriWriteOperations;
  ULONG KernelBumpedToNormalOperations;
  ULONG LowPriPagingReadOperations;
  ULONG KernelPagingReadsBumpedToNormal;
  ULONG LowPriPagingWriteOperations;
  ULONG KernelPagingWritesBumpedToNormal;
  ULONG BoostedIrpCount;
  ULONG BoostedPagingIrpCount;
  ULONG BlanketBoostCount;
} SYSTEM_LOW_PRIORITY_IO_INFORMATION, *PSYSTEM_LOW_PRIORITY_IO_INFORMATION; 
```

### SystemBootEntropyInformation
Enum value: 117
```
typedef enum _BOOT_ENTROPY_SOURCE_ID
{
  BootEntropySourceNone = 0,
  BootEntropySourceSeedfile = 1,
  BootEntropySourceExternal = 2,
  BootEntropySourceTpm = 3,
  BootEntropySourceRdrand = 4,
  BootEntropySourceTime = 5,
  BootEntropySourceAcpiOem0 = 6,
  BootEntropySourceUefi = 7,
  BootEntropySourceCng = 8,
  BootEntropySourceTcbTpm = 9,
  BootEntropySourceTcbRdrand = 10,
  BootMaxEntropySources = 10,
} BOOT_ENTROPY_SOURCE_ID, *PBOOT_ENTROPY_SOURCE_ID;

typedef enum _BOOT_ENTROPY_SOURCE_RESULT_CODE
{
  BootEntropySourceStructureUninitialized = 0,
  BootEntropySourceDisabledByPolicy = 1,
  BootEntropySourceNotPresent = 2,
  BootEntropySourceError = 3,
  BootEntropySourceSuccess = 4,
} BOOT_ENTROPY_SOURCE_RESULT_CODE, *PBOOT_ENTROPY_SOURCE_RESULT_CODE;

typedef struct _BOOT_ENTROPY_SOURCE_NT_RESULT
{
  enum _BOOT_ENTROPY_SOURCE_ID SourceId;
  ULONG64 Policy;
  enum _BOOT_ENTROPY_SOURCE_RESULT_CODE ResultCode;
  LONG ResultStatus;
  ULONG64 Time;
  ULONG EntropyLength;
  CHAR EntropyData[64];
  LONG __PADDING__[1];
} BOOT_ENTROPY_SOURCE_NT_RESULT, *PBOOT_ENTROPY_SOURCE_NT_RESULT; 

typedef struct _BOOT_ENTROPY_NT_RESULT
{
  ULONG maxEntropySources;
  BOOT_ENTROPY_SOURCE_NT_RESULT EntropySourceResult[10];
  CHAR SeedBytesForCng[48];
} BOOT_ENTROPY_NT_RESULT, *PBOOT_ENTROPY_NT_RESULT; x`
```

### SystemVerifierCountersInformation
Enum value: 118
```
typedef struct _SYSTEM_VERIFIER_COUNTERS_INFORMATION
{
  SYSTEM_VERIFIER_INFORMATION Legacy;
  ULONG RaiseIrqls;
  ULONG AcquireSpinLocks;
  ULONG SynchronizeExecutions;
  ULONG AllocationsWithNoTag;
  ULONG AllocationsFailed;
  ULONG AllocationsFailedDeliberately;
  ULONG64 LockedBytes;
  ULONG64 PeakLockedBytes;
  ULONG64 MappedLockedBytes;
  ULONG64 PeakMappedLockedBytes;
  ULONG64 MappedIoSpaceBytes;
  ULONG64 PeakMappedIoSpaceBytes;
  ULONG64 PagesForMdlBytes;
  ULONG64 PeakPagesForMdlBytes;
  ULONG64 ContiguousMemoryBytes;
  ULONG64 PeakContiguousMemoryBytes;
  ULONG ExecutePoolTypes;
  ULONG ExecutePageProtections;
  ULONG ExecutePageMappings;
  ULONG ExecuteWriteSections;
  ULONG SectionAlignmentFailures;
  ULONG IATInExecutableSection;
} SYSTEM_VERIFIER_COUNTERS_INFORMATION, *PSYSTEM_VERIFIER_COUNTERS_INFORMATION; 
```

### SystemNodeDistanceInformation
Enum value: 121

returns an array of ULONGs with NodeDistance information. Length of the array is the number of numa nodes in the system.

### SystemAcpiAuditInformation
Enum value: 122
```
typedef struct _SYSTEM_ACPI_AUDIT_INFORMATION
{
  ULONG RsdpCount;
  struct 
  {
    ULONG SameRsdt : 1; 
    ULONG SlicPresent : 1; 
    ULONG SlicDifferent : 1; 
  }; 
} SYSTEM_ACPI_AUDIT_INFORMATION, *PSYSTEM_ACPI_AUDIT_INFORMATION; 
```

### SystemBasicPerformanceInformation
Enum value: 123
```
typedef struct _SYSTEM_BASIC_PERFORMANCE_INFORMATION
{
  ULONG64 AvailablePages;
  ULONG64 CommittedPages;
  ULONG64 CommitLimit;
  ULONG64 PeakCommitment;
} SYSTEM_BASIC_PERFORMANCE_INFORMATION, *PSYSTEM_BASIC_PERFORMANCE_INFORMATION; 
```

### SystemQueryPerformanceCounterInformation
Enum value: 124
```
typedef struct _QUERY_PERFORMANCE_COUNTER_FLAGS
{
  union
  {
    struct 
    {
      ULONG KernelTransition : 1; 
      ULONG Reserved : 31; 
    }; 
    ULONG ul;
  }; 
} QUERY_PERFORMANCE_COUNTER_FLAGS, *PQUERY_PERFORMANCE_COUNTER_FLAGS; 

typedef struct _SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION
{
  ULONG Version;
  QUERY_PERFORMANCE_COUNTER_FLAGS Flags;
  QUERY_PERFORMANCE_COUNTER_FLAGS ValidFlags;
} SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION, *PSYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION; 
```

### SystemBootGraphicsInformation
Enum value: 126
```
typedef enum _SYSTEM_PIXEL_FORMAT
{
  SystemPixelFormatUnknown = 0,
  SystemPixelFormatR8G8B8 = 1,
  SystemPixelFormatR8G8B8X8 = 2,
  SystemPixelFormatB8G8R8 = 3,
  SystemPixelFormatB8G8R8X8 = 4,
} SYSTEM_PIXEL_FORMAT, *PSYSTEM_PIXEL_FORMAT;

typedef struct _SYSTEM_BOOT_GRAPHICS_INFORMATION
{
  LARGE_INTEGER FrameBuffer;
  ULONG Width;
  ULONG Height;
  ULONG PixelStride;
  ULONG Flags;
  enum _SYSTEM_PIXEL_FORMAT Format;
  ULONG DisplayRotation;
} SYSTEM_BOOT_GRAPHICS_INFORMATION, *PSYSTEM_BOOT_GRAPHICS_INFORMATION; 
```

### SystemScrubPhysicalMemoryInformation
Enum value: 127
```
typedef struct _MEMORY_SCRUB_INFORMATION
{
  PVOID Handle;
  ULONG64 PagesScrubbed;
} MEMORY_SCRUB_INFORMATION, *PMEMORY_SCRUB_INFORMATION; 
```

### SystemProcessorProfileControlArea
Enum value: 129
```
typedef struct _SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
{
  PROCESSOR_PROFILE_CONTROL_AREA* ProcessorProfileControlArea;
  CHAR Allocate;
  CHAR __PADDING__[7];
} SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA, *PSYSTEM_PROCESSOR_PROFILE_CONTROL_AREA; 
```

### SystemCombinePhysicalMemoryInformation
Enum value: 130
```
typedef struct _MEMORY_COMBINE_INFORMATION
{
  PVOID Handle;
  ULONG64 PagesCombined;
} MEMORY_COMBINE_INFORMATION, *PMEMORY_COMBINE_INFORMATION; 
```

### SystemEntropyInterruptTimingInformation
Enum value: 131
```
typedef struct _SYSTEM_ENTROPY_TIMING_INFORMATION
{
  PVOID EntropyRoutine ;
  PVOID InitializationRoutine ;
  PVOID InitializationContext;
} SYSTEM_ENTROPY_TIMING_INFORMATION, *PSYSTEM_ENTROPY_TIMING_INFORMATION; 
```

### SystemConsoleInformation
Enum value: 132
```
typedef struct _SYSTEM_CONSOLE_INFORMATION
{
  struct 
  {
    ULONG DriverLoaded : 1; 
    ULONG Spare : 31; 
  }; 
} SYSTEM_CONSOLE_INFORMATION, *PSYSTEM_CONSOLE_INFORMATION; 
```

### SystemPlatformBinaryInformation
Enum value: 133
```
typedef struct _SYSTEM_PLATFORM_BINARY_INFORMATION
{
  ULONG64 PhysicalAddress;
  PVOID HandoffBuffer;
  PVOID CommandLineBuffer;
  ULONG HandoffBufferSize;
  ULONG CommandLineBufferSize;
} SYSTEM_PLATFORM_BINARY_INFORMATION, *PSYSTEM_PLATFORM_BINARY_INFORMATION; 
```

### SystemPolicyInformation
Enum value: 134
```
typedef struct _SYSTEM_POLICY_INFORMATION
{
  PVOID InputData;
  PVOID OutputData;
  ULONG InputDataSize;
  ULONG OutputDataSize;
  ULONG Version;
  LONG __PADDING__[1];
} SYSTEM_POLICY_INFORMATION, *PSYSTEM_POLICY_INFORMATION; 
```

### SystemHypervisorProcessorCountInformation
Enum value: 135
```
typedef struct _SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
{
  ULONG NumberOfLogicalProcessors;
  ULONG NumberOfCores;
} SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION, *PSYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION; 
```

### SystemDeviceDataInformation + SystemDeviceDataEnumerationInformation
Enum value: 136 + 137
```
typedef struct _SYSTEM_DEVICE_DATA_INFORMATION
{
  UNICODE_STRING DeviceId;
  UNICODE_STRING DataName;
  ULONG DataType;
  ULONG DataBufferLength;
  PVOID DataBuffer;
} SYSTEM_DEVICE_DATA_INFORMATION, *PSYSTEM_DEVICE_DATA_INFORMATION; 
```

### SystemMemoryTopologyInformation
Enum value: 138
```
typedef struct _PHYSICAL_CHANNEL_RUN
{
  ULONG NodeNumber;
  ULONG ChannelNumber;
  ULONG64 BasePage;
  ULONG64 PageCount;
  ULONG64 Flags;
} PHYSICAL_CHANNEL_RUN, *PPHYSICAL_CHANNEL_RUN; 

typedef struct _SYSTEM_MEMORY_TOPOLOGY_INFORMATION
{
  ULONG64 NumberOfRuns;
  ULONG NumberOfNodes;
  ULONG NumberOfChannels;
  PHYSICAL_CHANNEL_RUN Run[1];
} SYSTEM_MEMORY_TOPOLOGY_INFORMATION, *PSYSTEM_MEMORY_TOPOLOGY_INFORMATION; 
```

### SystemMemoryChannelInformation
Enum value: 139
```
typedef struct _SYSTEM_MEMORY_CHANNEL_INFORMATION
{
  ULONG ChannelNumber;
  ULONG ChannelHeatIndex;
  ULONG64 TotalPageCount;
  ULONG64 ZeroPageCount;
  ULONG64 FreePageCount;
  ULONG64 StandbyPageCount;
} SYSTEM_MEMORY_CHANNEL_INFORMATION, *PSYSTEM_MEMORY_CHANNEL_INFORMATION; 
```

### SystemBootLogoInformation
Enum value: 140
```
typedef struct _SYSTEM_BOOT_LOGO_INFORMATION
{
  ULONG Flags;
  ULONG BitmapOffset;
} SYSTEM_BOOT_LOGO_INFORMATION, *PSYSTEM_BOOT_LOGO_INFORMATION; 
```

### SystemSecureBootPolicyInformation
Enum value: 143
```
typedef struct _SYSTEM_SECUREBOOT_POLICY_INFORMATION
{
  GUID PolicyPublisher;
  ULONG PolicyVersion;
  ULONG PolicyOptions;
} SYSTEM_SECUREBOOT_POLICY_INFORMATION, *PSYSTEM_SECUREBOOT_POLICY_INFORMATION; 
```

### SystemPageFileInformationEx
Enum value: 144
```
typedef struct _SYSTEM_PAGEFILE_INFORMATION_EX
{
  SYSTEM_PAGEFILE_INFORMATION Info;
  ULONG MinimumSize;
  ULONG MaximumSize;
} SYSTEM_PAGEFILE_INFORMATION_EX, *PSYSTEM_PAGEFILE_INFORMATION_EX; 
```

### SystemSecureBootInformation
Enum value: 145
```
typedef struct _SYSTEM_SECUREBOOT_INFORMATION
{
  CHAR SecureBootEnabled;
  CHAR SecureBootCapable;
} SYSTEM_SECUREBOOT_INFORMATION, *PSYSTEM_SECUREBOOT_INFORMATION; 
```

### SystemPortableWorkspaceEfiLauncherInformation
Enum value: 147
```
typedef struct _SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
{
  UCHAR EfiLauncherEnabled;
} SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION, *PSYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION; 
```

### SystemKernelDebuggerInformationEx
Enum value: 149
```
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
  CHAR DebuggerAllowed;
  CHAR DebuggerEnabled;
  CHAR DebuggerPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX; 
```

### SystemSoftRebootInformation
Enum value: 151
```
typedef struct _SYSTEM_SOFT_REBOOT_INFORMATION
{
	ULONG SoftRebootFlags;
} SYSTEM_SOFT_REBOOT_INFORMATION, *PSYSTEM_SOFT_REBOOT_INFORMATION;
```

### SystemElamCertificateInformation
Enum value: 152
```
typedef struct _SYSTEM_ELAM_CERTIFICATE_INFORMATION
{
  PVOID ElamDriverFile;
} SYSTEM_ELAM_CERTIFICATE_INFORMATION, *PSYSTEM_ELAM_CERTIFICATE_INFORMATION; 
```

### SystemOfflineDumpConfigInformation
Enum value: 153
```
typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
{
  ULONG Version;
  ULONG AbnormalResetOccurred;
  ULONG OfflineMemoryDumpCapable;
  LARGE_INTEGER ResetDataAddress;
  ULONG ResetDataSize;
  LONG __PADDING__[1];
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2, *POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2; 
```

### SystemProcessorFeaturesInformation
Enum value: 154
```
typedef struct _SYSTEM_PROCESSOR_FEATURES_INFORMATION
{
  ULONG64 ProcessorFeatureBits;
  ULONG64 Reserved[3];
} SYSTEM_PROCESSOR_FEATURES_INFORMATION, *PSYSTEM_PROCESSOR_FEATURES_INFORMATION; 
```

### SystemManufacturingInformation
Enum value: 157
```
typedef struct _SYSTEM_MANUFACTURING_INFORMATION
{
  ULONG Options;
  UNICODE_STRING ProfileName;
} SYSTEM_MANUFACTURING_INFORMATION, *PSYSTEM_MANUFACTURING_INFORMATION; 
```

### SystemEnergyEstimationConfigInformation
Enum value: 158
```
typedef struct _SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
{
  CHAR Enabled;
} SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION, *PSYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION; 
```

### SystemHypervisorDetailInformation
Enum value: 159
```
typedef struct _HV_DETAILS
{
  ULONG Data[4];
} HV_DETAILS, *PHV_DETAILS; 

typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION
{
  HV_DETAILS HvVendorAndMaxFunction;
  HV_DETAILS HypervisorInterface;
  HV_DETAILS HypervisorVersion;
  HV_DETAILS HvFeatures;
  HV_DETAILS HwFeatures;
  HV_DETAILS EnlightenmentInfo;
  HV_DETAILS ImplementationLimits;
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION, *PSYSTEM_HYPERVISOR_DETAIL_INFORMATION; 
```

### SystemProcessorCycleStatsInformation
Enum value: 160
```
typedef struct _SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION
{
  ULONG64 Cycles[2][4];
} SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION, *PSYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION; 
```

### SystemTrustedPlatformModuleInformation
Enum value: 162
```
typedef struct _SYSTEM_TPM_INFORMATION
{
  ULONG Flags;
} SYSTEM_TPM_INFORMATION, *PSYSTEM_TPM_INFORMATION; 
```

### SystemKernelDebuggerFlags
Enum value: 163
```
typedef struct _SYSTEM_KERNEL_DEBUGGER_FLAGS
{
  CHAR KernelDebuggerIgnoreUmExceptions;
} SYSTEM_KERNEL_DEBUGGER_FLAGS, *PSYSTEM_KERNEL_DEBUGGER_FLAGS; 
```

### SystemCodeIntegrityPolicyInformation
Enum value: 164
```
typedef struct _SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
{
  ULONG Options;
  ULONG HVCIOptions;
  ULONG64 Version;
  GUID PolicyGuid;
} SYSTEM_CODEINTEGRITYPOLICY_INFORMATION, *PSYSTEM_CODEINTEGRITYPOLICY_INFORMATION; 
```

### SystemIsolatedUserModeInformation
Enum value: 165
```
typedef struct _SYSTEM_ISOLATED_USER_MODE_INFORMATION
{
  struct 
  {
    CHAR SecureKernelRunning : 1; 
    CHAR HvciEnabled : 1; 
    CHAR HvciStrictMode : 1; 
    CHAR DebugEnabled : 1; 
    CHAR FirmwarePageProtection : 1; 
    CHAR EncryptionKeyAvailable : 1; 
    CHAR SpareFlags : 2; 
  }; 
  struct 
  {
    CHAR TrustletRunning : 1; 
    CHAR HvciDisableAllowed : 1; 
    CHAR HardwareEnforcedVbs : 1; 
    CHAR NoSecrets : 1; 
    CHAR SpareFlags2 : 4; 
  }; 
  CHAR Spare0[6];
  ULONG64 Spare1;
} SYSTEM_ISOLATED_USER_MODE_INFORMATION, *PSYSTEM_ISOLATED_USER_MODE_INFORMATION; 
```

### SystemSingleModuleInformation
Enum value: 167
```
typedef struct _SYSTEM_SINGLE_MODULE_INFORMATION
{
  PVOID TargetModuleAddress;
  RTL_PROCESS_MODULE_INFORMATION_EX ExInfo;
} SYSTEM_SINGLE_MODULE_INFORMATION, *PSYSTEM_SINGLE_MODULE_INFORMATION; 
```

### SystemAllowedCpuSetsInformation
Enum value: 168
```
typedef struct _SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
{
  ULONG64 WorkloadClass;
  ULONG64 CpuSets[1];
} SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION, *PSYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION; 
```

### SystemVsmProtectionInformation
Enum value: 169
```
typedef struct _SYSTEM_VSM_PROTECTION_INFORMATION
{
  CHAR DmaProtectionsAvailable;
  CHAR DmaProtectionsInUse;
  CHAR HardwareMbecAvailable;
  CHAR ApicVirtualizationAvailable;
} SYSTEM_VSM_PROTECTION_INFORMATION, *PSYSTEM_VSM_PROTECTION_INFORMATION; 
```

### SystemInterruptCpuSetsInformation
Enum value: 170
```
typedef struct _SYSTEM_INTERRUPT_CPU_SET_INFORMATION
{
  ULONG Gsiv;
  USHORT Group;
  ULONG64 CpuSets;
} SYSTEM_INTERRUPT_CPU_SET_INFORMATION, *PSYSTEM_INTERRUPT_CPU_SET_INFORMATION; 
```

### SystemSecureBootPolicyFullInformation
Enum value: 171
```
typedef struct _SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
{
  SYSTEM_SECUREBOOT_POLICY_INFORMATION PolicyInformation;
  ULONG PolicySize;
  CHAR Policy[1];
  CHAR __PADDING__[3];
} SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION, *PSYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION; 
```

### SystemRootSiloInformation
Enum value: 174
```
typedef struct _SYSTEM_ROOT_SILO_INFORMATION
{
  ULONG NumberOfSilos;
  ULONG SiloIdList[1];
} SYSTEM_ROOT_SILO_INFORMATION, *PSYSTEM_ROOT_SILO_INFORMATION; 
```

### SystemCpuSetInformation
Enum value: 175
```
typedef enum _CPU_SET_INFORMATION_TYPE
{
  CpuSetInformation = 0,
} CPU_SET_INFORMATION_TYPE, *PCPU_SET_INFORMATION_TYPE;

typedef struct _SYSTEM_CPU_SET_INFORMATION
{
  ULONG Size;
  enum _CPU_SET_INFORMATION_TYPE Type;
  struct
  {
    ULONG Id;
    USHORT Group;
    CHAR LogicalProcessorIndex;
    CHAR CoreIndex;
    CHAR LastLevelCacheIndex;
    CHAR NumaNodeIndex;
    CHAR EfficiencyClass;
    union
    {
      CHAR AllFlags;
      struct 
      {
        CHAR Parked : 1; 
        CHAR Allocated : 1; 
        CHAR AllocatedToTargetProcess : 1; 
        CHAR RealTime : 1; 
        CHAR ReservedFlags : 4; 
      }; 
    }; 
    union
    {
      ULONG Reserved;
      CHAR SchedulingClass;
    }; 
    ULONG64 AllocationTag;
  } CpuSet;
} SYSTEM_CPU_SET_INFORMATION, *PSYSTEM_CPU_SET_INFORMATION; 
```

### SystemCpuSetTagInformation
Enum value: 176
```
typedef struct _SYSTEM_CPU_SET_TAG_INFORMATION
{
  ULONG64 Tag;
  ULONG64 CpuSets[1];
} SYSTEM_CPU_SET_TAG_INFORMATION, *PSYSTEM_CPU_SET_TAG_INFORMATION; 
```

### SystemSecureKernelProfileInformation
Enum value: 178
```
typedef struct _SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
{
  ULONG ExtentCount;
  ULONG ValidStructureSize;
  ULONG NextExtentIndex;
  ULONG ExtentRestart;
  ULONG CycleCount;
  ULONG TimeoutCount;
  ULONG64 CycleTime;
  ULONG64 CycleTimeMax;
  ULONG64 ExtentTime;
  ULONG ExtentTimeIndex;
  ULONG ExtentTimeMaxIndex;
  ULONG64 ExtentTimeMax;
  ULONG64 HyperFlushTimeMax;
  ULONG64 TranslateVaTimeMax;
  ULONG64 DebugExemptionCount;
  ULONG64 TbHitCount;
  ULONG64 TbMissCount;
  ULONG64 VinaPendingYield;
  ULONG64 HashCycles;
  ULONG HistogramOffset;
  ULONG HistogramBuckets;
  ULONG HistogramShift;
  ULONG Reserved1;
  ULONG64 PageNotPresentCount;
} SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION, *PSYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION; 
```

### SystemInterruptSteeringInformation
Enum value: 180
```
typedef struct _SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT
{
  union
  {
    struct 
    {
      ULONG Enabled : 1; 
      ULONG Reserved : 31; 
    }; 
    ULONG AsULONG;
  }; 
} SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT, *PSYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT; 
```

### SystemSupportedProcessorArchitectures
Enum value: 181
```
typedef struct _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION
{
  struct 
  {
    ULONG Machine : 16; 
    ULONG KernelMode : 1; 
    ULONG UserMode : 1; 
    ULONG Native : 1; 
    ULONG Process : 1; 
    ULONG WoW64Container : 1; 
    ULONG ReservedZero0 : 11; 
  }; 
} SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION, *PSYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION; 
```

### SystemMemoryUsageInformation
Enum value: 182
```
typedef struct _SYSTEM_MEMORY_USAGE_INFORMATION
{
  ULONG64 TotalPhysicalBytes;
  ULONG64 AvailableBytes;
  __int64 ResidentAvailableBytes;
  ULONG64 CommittedBytes;
  ULONG64 SharedCommittedBytes;
  ULONG64 CommitLimitBytes;
  ULONG64 PeakCommitmentBytes;
} SYSTEM_MEMORY_USAGE_INFORMATION, *PSYSTEM_MEMORY_USAGE_INFORMATION; 
```

### SystemCodeIntegrityCertificateInformation
Enum value: 183
```
typedef struct _SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
{
  PVOID ImageFile;
  ULONG Type;
  LONG __PADDING__[1];
} SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION, *PSYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION; 
```

### SystemPhysicalMemoryInformation
Enum value: 184
```
typedef struct _SYSTEM_PHYSICAL_MEMORY_INFORMATION
{
  ULONG64 TotalPhysicalBytes;
  ULONG64 LowestPhysicalAddress;
  ULONG64 HighestPhysicalAddress;
} SYSTEM_PHYSICAL_MEMORY_INFORMATION, *PSYSTEM_PHYSICAL_MEMORY_INFORMATION; 
```

### SystemKernelDebuggingAllowed
Enum value: 186

returns boolean indicating if kernel debugging is allowed

### SystemActivityModerationExeState
Enum value: 187
```
typedef enum _SYSTEM_ACTIVITY_MODERATION_STATE
{
  SystemActivityModerationStateSystemManaged = 0,
  SystemActivityModerationStateUserManagedAllowThrottling = 1,
  SystemActivityModerationStateUserManagedDisableThrottling = 2,
  MaxSystemActivityModerationState = 3,
} SYSTEM_ACTIVITY_MODERATION_STATE, *PSYSTEM_ACTIVITY_MODERATION_STATE;
```

### SystemActivityModerationUserSettings
Enum value: 188
```
typedef struct _SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
{
  PVOID UserKeyHandle;
} SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS, *PSYSTEM_ACTIVITY_MODERATION_USER_SETTINGS; 
```

### SystemCodeIntegrityUnlockInformation
Enum value: 190
```
typedef struct _SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
{
  union
  {
    ULONG Flags;
    struct 
    {
      ULONG Locked : 1; 
      ULONG UnlockApplied : 1; 
      ULONG UnlockIdValid : 1; 
      ULONG Reserved : 29; 
    }; 
  }; 
  CHAR UnlockId[32];
} SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION, *PSYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION; 
```

### SystemFlushInformation
Enum value: 192
```
typedef struct _SYSTEM_FLUSH_INFORMATION
{
  ULONG SupportedFlushMethods;
  ULONG ProcessorCacheFlushSize;
  ULONG64 SystemFlushCapabilities;
  ULONG64 Reserved[2];
} SYSTEM_FLUSH_INFORMATION, *PSYSTEM_FLUSH_INFORMATION; 
```

### SystemWriteConstraintInformation
Enum value: 195
```
typedef struct _SYSTEM_WRITE_CONSTRAINT_INFORMATION
{
  ULONG WriteConstraintPolicy;
  ULONG Reserved;
} SYSTEM_WRITE_CONSTRAINT_INFORMATION, *PSYSTEM_WRITE_CONSTRAINT_INFORMATION; 
```

### SystemKernelVaShadowInformation
Enum value: 196
```
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
  struct
  {
    struct 
    {
      ULONG KvaShadowEnabled : 1; 
      ULONG KvaShadowUserGlobal : 1; 
      ULONG KvaShadowPcid : 1; 
      ULONG KvaShadowInvpcid : 1; 
      ULONG KvaShadowRequired : 1; 
      ULONG KvaShadowRequiredAvailable : 1; 
      ULONG InvalidPteBit : 6; 
      ULONG L1DataCacheFlushSupported : 1; 
      ULONG L1TerminalFaultMitigationPresent : 1; 
      ULONG Reserved : 18; 
    }; 
  } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION; 
```

### SystemHypervisorSharedPageInformation
Enum value: 197
```
typedef struct _SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION
{
  PVOID HypervisorSharedUserVa;
} SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION, *PSYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION; 
```

### SystemCodeIntegrityVerificationInformation
Enum value: 199
```
typedef struct _SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
{
  PVOID FileHandle;
  ULONG ImageSize;
  PVOID Image;
} SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION, *PSYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION; 
```

### SystemFirmwarePartitionInformation
Enum value: 200
```
typedef struct _SYSTEM_FIRMWARE_PARTITION_INFORMATION
{
  UNICODE_STRING FirmwarePartition;
} SYSTEM_FIRMWARE_PARTITION_INFORMATION, *PSYSTEM_FIRMWARE_PARTITION_INFORMATION; 
```

### SystemSpeculationControlInformation
Enum value: 201
```
typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION
{
  struct
  {
    struct 
    {
      ULONG BpbEnabled : 1; 
      ULONG BpbDisabledSystemPolicy : 1; 
      ULONG BpbDisabledNoHardwareSupport : 1; 
      ULONG SpecCtrlEnumerated : 1; 
      ULONG SpecCmdEnumerated : 1; 
      ULONG IbrsPresent : 1; 
      ULONG StibpPresent : 1; 
      ULONG SmepPresent : 1; 
      ULONG SpeculativeStoreBypassDisableAvailable : 1; 
      ULONG SpeculativeStoreBypassDisableSupported : 1; 
      ULONG SpeculativeStoreBypassDisabledSystemWide : 1; 
      ULONG SpeculativeStoreBypassDisabledKernel : 1; 
      ULONG SpeculativeStoreBypassDisableRequired : 1; 
      ULONG BpbDisabledKernelToUser : 1; 
      ULONG SpecCtrlRetpolineEnabled : 1; 
      ULONG SpecCtrlImportOptimizationEnabled : 1; 
      ULONG EnhancedIbrs : 1; 
      ULONG HvL1tfStatusAvailable : 1; 
      ULONG HvL1tfProcessorNotAffected : 1; 
      ULONG HvL1tfMigitationEnabled : 1; 
      ULONG HvL1tfMigitationNotEnabled_Hardware : 1; 
      ULONG HvL1tfMigitationNotEnabled_LoadOption : 1; 
      ULONG HvL1tfMigitationNotEnabled_CoreScheduler : 1; 
      ULONG EnhancedIbrsReported : 1; 
      ULONG MdsHardwareProtected : 1; 
      ULONG MbClearEnabled : 1; 
      ULONG MbClearReported : 1; 
      ULONG Reserved : 5; 
    }; 
  } SpeculationControlFlags;
} SYSTEM_SPECULATION_CONTROL_INFORMATION, *PSYSTEM_SPECULATION_CONTROL_INFORMATION; 
```

### SystemDmaGuardPolicyInformation
Enum value: 202
```
typedef struct _SYSTEM_DMA_GUARD_POLICY_INFORMATION
{
  CHAR DmaGuardPolicyEnabled;
} SYSTEM_DMA_GUARD_POLICY_INFORMATION, *PSYSTEM_DMA_GUARD_POLICY_INFORMATION; 
```

### SystemEnclaveLaunchControlInformation
Enum value: 203
```
typedef struct _SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
{
  CHAR EnclaveLaunchSigner[32];
} SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION, *PSYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION; 
```

### SystemWorkloadAllowedCpuSetsInformation
Enum value: 204
```
typedef struct _SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
{
  ULONG64 WorkloadClass;
  ULONG64 CpuSets[1];
} SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION, *PSYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION; 
```

### SystemCodeIntegrityUnlockModeInformation
Enum value: 205
```
typedef struct _SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
{
  union
  {
    ULONG Flags;
    struct 
    {
      ULONG Locked : 1; 
      ULONG UnlockApplied : 1; 
      ULONG UnlockIdValid : 1; 
      ULONG Reserved : 29; 
    }; 
  }; 
  CHAR UnlockId[32];
} SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION, *PSYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION; 
```

### SystemLeapSecondInformation
Enum value: 206
```
typedef struct _SYSTEM_LEAP_SECOND_INFORMATION
{
  CHAR Enabled;
  ULONG Flags;
} SYSTEM_LEAP_SECOND_INFORMATION, *PSYSTEM_LEAP_SECOND_INFORMATION; 
```

### SystemSecurityModelInformation
Enum value: 208
```
typedef struct _SYSTEM_SECURITY_MODEL_INFORMATION
{
  struct
  {
    struct 
    {
      ULONG ReservedFlag : 1; 
      ULONG AllowDeviceOwnerProtectionDowngrade : 1; 
      ULONG Reserved : 30; 
    }; 
  } SecurityModelFlags;
} SYSTEM_SECURITY_MODEL_INFORMATION, *PSYSTEM_SECURITY_MODEL_INFORMATION; 
```

### SystemFeatureConfigurationInformation
Enum value: 210
```
typedef struct _RTL_FEATURE_CONFIGURATION
{
  unsigned int FeatureId;
  struct 
  {
    unsigned int Priority : 4; 
    unsigned int EnabledState : 2; 
    unsigned int IsWexpConfiguration : 1; 
    unsigned int HasSubscriptions : 1; 
    unsigned int Variant : 6; 
    unsigned int VariantPayloadKind : 2; 
  }; 
  unsigned int VariantPayload;
} RTL_FEATURE_CONFIGURATION, *PRTL_FEATURE_CONFIGURATION; 

typedef struct _SYSTEM_FEATURE_CONFIGURATION_INFORMATION
{
  ULONG64 ChangeStamp;
  RTL_FEATURE_CONFIGURATION Configuration;
  LONG __PADDING__[1];
} SYSTEM_FEATURE_CONFIGURATION_INFORMATION, *PSYSTEM_FEATURE_CONFIGURATION_INFORMATION; 
```

### SystemFeatureConfigurationSectionInformation
Enum value: 211
```
typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY
{
  ULONG64 ChangeStamp;
  PVOID Section;
  ULONG64 Size;
} SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY, *PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY; 

typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
{
  ULONG64 OverallChangeStamp;
  SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY Descriptors[3];
} SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION, *PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION; 
```

### SystemFeatureUsageSubscriptionInformation
Enum value: 212
```
typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET
{
  ULONG Data[2];
} RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET, *PRTL_FEATURE_USAGE_SUBSCRIPTION_TARGET; 

typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS
{
  unsigned int FeatureId;
  USHORT ReportingKind;
  USHORT ReportingOptions;
  RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET ReportingTarget;
} RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS, *PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS; 
```

### SystemFwRamdiskInformation
Enum value: 215
```
typedef struct _SYSTEM_FIRMWARE_RAMDISK_INFORMATION
{
  ULONG Version;
  ULONG BlockSize;
  ULONG64 BaseAddress;
  ULONG64 Size;
} SYSTEM_FIRMWARE_RAMDISK_INFORMATION, *PSYSTEM_FIRMWARE_RAMDISK_INFORMATION; 
```

### SystemDifSetRuleClassInformation
Enum valie: 217

typedef struct _SYSTEM_DIF_VOLATILE_INFORMATION
{
  ULONG RuleClasses[2];
  ULONG VerifierOption;
  ULONG TriageContext;
} SYSTEM_DIF_VOLATILE_INFORMATION, *PSYSTEM_DIF_VOLATILE_INFORMATION; 

### SystemDifClearRuleClassInformation
Enum value: 218

Takes no input data.

### SystemDifApplyPluginVerificationOnDriver + SystemDifRemovePluginVerificationOnDriver
Enum values: 219 + 220
```
typedef struct _SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
{
  UNICODE_STRING DriverName;
} SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION, *PSYSTEM_DIF_PLUGIN_DRIVER_INFORMATION;
```

### SystemShadowStackInformation
Enum value: 221
```
typedef struct _SYSTEM_SHADOW_STACK_INFORMATION
{
  union
  {
    ULONG Flags;
    struct 
    {
      ULONG CetCapable : 1; 
      ULONG UserCetAllowed : 1; 
      ULONG ReservedForUserCet : 6; 
      ULONG KernelCetEnabled : 1; 
      ULONG KernelCetAuditModeEnabled : 1; 
      ULONG ReservedForKernelCet : 6; 
      ULONG Reserved : 16; 
    }; 
  }; 
} SYSTEM_SHADOW_STACK_INFORMATION, *PSYSTEM_SHADOW_STACK_INFORMATION; 
```

### SystemBuildVersionInformation
Enum value: 222
```
typedef struct _SYSTEM_BUILD_VERSION_INFORMATION
{
  USHORT LayerNumber;
  USHORT LayerCount;
  ULONG OsMajorVersion;
  ULONG OsMinorVersion;
  ULONG NtBuildNumber;
  ULONG NtBuildQfe;
  CHAR LayerName[128];
  CHAR NtBuildBranch[128];
  CHAR NtBuildLab[128];
  CHAR NtBuildLabEx[128];
  CHAR NtBuildStamp[26];
  CHAR NtBuildArch[16];
  union
  {
    union
    {
      ULONG Value32;
      struct 
      {
        ULONG IsTopLevel : 1; 
        ULONG IsChecked : 1; 
      }; 
    }; 
  } Flags;
} SYSTEM_BUILD_VERSION_INFORMATION, *PSYSTEM_BUILD_VERSION_INFORMATION; 
```

### SystemPoolLimitInformation
Enum value: 223
```
typedef struct _SYSTEM_POOL_LIMIT_MEM_INFO
{
  ULONG64 MemoryLimit;
  ULONG64 NotificationLimit;
} SYSTEM_POOL_LIMIT_MEM_INFO, *PSYSTEM_POOL_LIMIT_MEM_INFO; 

typedef struct _WNF_STATE_NAME
{
  ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME; 

typedef struct _SYSTEM_POOL_LIMIT_INFO
{
  ULONG PoolTag;
  SYSTEM_POOL_LIMIT_MEM_INFO MemLimits[2];
  WNF_STATE_NAME NotificationHandle;
} SYSTEM_POOL_LIMIT_INFO, *PSYSTEM_POOL_LIMIT_INFO; 

typedef struct _SYSTEM_POOL_LIMIT_INFORMATION
{
  ULONG Version;
  ULONG EntryCount;
  SYSTEM_POOL_LIMIT_INFO LimitEntries[1];
} SYSTEM_POOL_LIMIT_INFORMATION, *PSYSTEM_POOL_LIMIT_INFORMATION; 
```

### SystemCodeIntegrityAddDynamicStore + SystemCodeIntegrityClearDynamicStores
Enum values: 224 + 225

Takes no input data.

### SystemDifPoolTrackingInformatio
Enum value: 226

Takes in no input data.

### SystemPoolZeroingInformation
Enum value: 227
```
typedef struct _SYSTEM_POOL_ZEROING_INFORMATION
{
  UCHAR PoolZeroingSupportPresent;
} SYSTEM_POOL_ZEROING_INFORMATION, *PSYSTEM_POOL_ZEROING_INFORMATION; 
```

### SystemDpcWatchdogInformation
Enum value: 228
```
typedef struct _SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
{
  union
  {
    struct 
    {
      ULONG Version : 8; 
      ULONG AllFlags : 24; 
    }; 
    struct
    {
      struct 
      {
        ULONG Dummy : 8; 
        ULONG SingleDpcTimeLimitPresent : 1; 
        ULONG CumulativeDpcTimeLimitPresent : 1; 
        ULONG SingleDpcSoftTimeLimitPresent : 1; 
        ULONG CumulativeDpcSoftTimeLimitPresent : 1; 
        ULONG Reserved : 20; 
      }; 
    } Flags;
  }; 
  ULONG SingleDpcTimeLimitMs;
  ULONG CumulativeDpcTimeLimitMs;
  ULONG SingleDpcSoftTimeLimitMs;
  ULONG CumulativeDpcSoftTimeLimitMs;
} SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION, *PSYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION; 
```

### SystemDpcWatchdogInformation2
Enum value: 229
```
typedef struct _SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
{
  union
  {
    struct 
    {
      ULONG Version : 8; 
      ULONG AllFlags : 24; 
    }; 
    struct
    {
      struct 
      {
        ULONG Dummy : 8; 
        ULONG SingleDpcTimeLimitPresent : 1; 
        ULONG CumulativeDpcTimeLimitPresent : 1; 
        ULONG SingleDpcSoftTimeLimitPresent : 1; 
        ULONG CumulativeDpcSoftTimeLimitPresent : 1; 
        ULONG SingleDpcProfileThresholdPresent : 1; 
        ULONG CumulativeDpcProfileThresholdPresent : 1; 
        ULONG ProfileBufferSizePresent : 1; 
        ULONG Reserved : 17; 
      }; 
    } Flags;
  }; 
  ULONG SingleDpcTimeLimitMs;
  ULONG CumulativeDpcTimeLimitMs;
  ULONG SingleDpcSoftTimeLimitMs;
  ULONG CumulativeDpcSoftTimeLimitMs;
  ULONG SingleDpcProfileThresholdMs;
  ULONG CumulativeDpcProfileThresholdMs;
  ULONG ProfileBufferSizeBytes;
} SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2, *PSYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2; 
```

### SystemSingleProcessorRelationshipInformation
Enum value: 231
```
typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP
{
  RelationProcessorCore = 0,
  RelationNumaNode = 1,
  RelationCache = 2,
  RelationProcessorPackage = 3,
  RelationGroup = 4,
  RelationProcessorDie = 5,
  RelationNumaNodeEx = 6,
  RelationProcessorModule = 7,
  RelationAll = 0xffffffff,
} LOGICAL_PROCESSOR_RELATIONSHIP, *PLOGICAL_PROCESSOR_RELATIONSHIP;

typedef struct _PROCESSOR_NUMBER
{
  USHORT Group;
  CHAR Number;
  CHAR Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER; 

typedef struct _SYSTEM_SINGLE_PROCESSOR_RELATIONSHIP_INFORMATION_REQUEST
{
  enum _LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
  PROCESSOR_NUMBER ProcessorNumber;
} SYSTEM_SINGLE_PROCESSOR_RELATIONSHIP_INFORMATION_REQUEST, *PSYSTEM_SINGLE_PROCESSOR_RELATIONSHIP_INFORMATION_REQUEST; 
```

### SystemXfgCheckFailureInformation
Enum value: 232
```
typedef struct _SYSTEM_XFG_FAILURE_INFORMATION
{
  PVOID ReturnAddress;
  PVOID TargetAddress;
  ULONG DispatchMode;
  ULONG64 XfgValue;
} SYSTEM_XFG_FAILURE_INFORMATION, *PSYSTEM_XFG_FAILURE_INFORMATION; 
```

### SystemIommuStateInformation
Enum value: 233
```
typedef enum _SYSTEM_IOMMU_STATE
{
  IommuStateBlock = 0,
  IommuStateUnblock = 1,
} SYSTEM_IOMMU_STATE, *PSYSTEM_IOMMU_STATE;

typedef struct _SYSTEM_IOMMU_STATE_INFORMATION
{
  enum _SYSTEM_IOMMU_STATE State;
  PVOID Pdo;
} SYSTEM_IOMMU_STATE_INFORMATION, *PSYSTEM_IOMMU_STATE_INFORMATION; 
```

### SystemHypervisorMinrootInformation
Enum value: 234
```
typedef struct _HV_MINROOT_NUMA_LPS
{
  ULONG NodeIndex;
  ULONG64 Mask[16];
} HV_MINROOT_NUMA_LPS, *PHV_MINROOT_NUMA_LPS; 

typedef struct _SYSTEM_HYPERVISOR_MINROOT_INFORMATION
{
  ULONG NumProc;
  ULONG RootProc;
  ULONG RootProcNumaNodesSpecified;
  USHORT RootProcNumaNodes[64];
  ULONG RootProcPerCore;
  ULONG RootProcPerNode;
  ULONG RootProcNumaNodesLpsSpecified;
  HV_MINROOT_NUMA_LPS RootProcNumaNodeLps[64];
} SYSTEM_HYPERVISOR_MINROOT_INFORMATION, *PSYSTEM_HYPERVISOR_MINROOT_INFORMATION; 
```

### SystemHypervisorBootPagesInformation
Enum value: 235
```
typedef struct _SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
{
  ULONG RangeCount;
  ULONG Pad;
  ULONG64 RangeArray[1];
} SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION, *PSYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION; 
```

### SystemPointerAuthInformation
Enum value: 236
```
typedef struct _SYSTEM_POINTER_AUTH_INFORMATION
{
  union
  {
    USHORT SupportedFlags;
    struct 
    {
      USHORT AddressAuthSupported : 1; 
      USHORT AddressAuthQarma : 1; 
      USHORT GenericAuthSupported : 1; 
      USHORT GenericAuthQarma : 1; 
      USHORT SupportedReserved : 12; 
    }; 
  }; 
  union
  {
    USHORT EnabledFlags;
    struct 
    {
      USHORT UserPerProcessIpAuthEnabled : 1; 
      USHORT UserGlobalIpAuthEnabled : 1; 
      USHORT UserEnabledReserved : 6; 
      USHORT KernelIpAuthEnabled : 1; 
      USHORT KernelEnabledReserved : 7; 
    }; 
  }; 
} SYSTEM_POINTER_AUTH_INFORMATION, *PSYSTEM_POINTER_AUTH_INFORMATION; 
```
