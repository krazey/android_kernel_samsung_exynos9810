# UFSHCD makefile
obj-$(CONFIG_SCSI_UFSHCD) += ufshcd-core.o
ufshcd-core-y := ufshcd.o ufs_quirks.o
obj-$(CONFIG_SCSI_UFSHCD_PCI) += ufshcd-pci.o
obj-$(CONFIG_SCSI_UFSHCD_PLATFORM) += ufshcd-pltfrm.o
ufshcd-core-$(CONFIG_SCSI_UFS_CRYPTO) += ufshcd-crypto.o
obj-$(CONFIG_SCSI_UFS_EXYNOS) += ufs-exynos.o ufs-exynos-dbg.o
obj-$(CONFIG_SCSI_UFS_EXYNOS_FMP) += ufs-exynos-fmp.o
obj-$(CONFIG_SOC_EXYNOS9810) += ufs-cal-9810.o
