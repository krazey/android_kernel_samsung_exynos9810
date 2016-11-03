.. The Linux Kernel documentation master file, created by
   sphinx-quickstart on Fri Feb 12 13:51:46 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to The Linux Kernel's documentation
===========================================

This is the top level of the kernel's documentation tree.  Kernel
documentation, like the kernel itself, is very much a work in progress;
that is especially true as we work to integrate our many scattered
documents into a coherent whole.  Please note that improvements to the
documentation are welcome; join the linux-doc list at vger.kernel.org if
you want to help out.

User-oriented documentation
---------------------------

The following manuals are written for *users* of the kernel — those who are
trying to get it to work optimally on a given system.

.. toctree::
   :maxdepth: 2

   admin-guide/index

Introduction to kernel development
----------------------------------

These manuals contain overall information about how to develop the kernel.
The kernel community is quite large, with thousands of developers
contributing over the course of a year.  As with any large community,
knowing how things are done will make the process of getting your changes
merged much easier.

.. toctree::
   :maxdepth: 2

   process/index
   dev-tools/index
   driver-api/index
   media/index
   gpu/index
   tpm/index
   80211/index

This section describes CPU vulnerabilities and their mitigations.

.. toctree::
   :maxdepth: 1

   hw-vuln/index

Architecture-specific documentation
-----------------------------------

These books provide programming details about architecture-specific
implementation.

.. toctree::
   :maxdepth: 2

   x86/index
   core-api/index

Indices and tables
==================

* :ref:`genindex`
