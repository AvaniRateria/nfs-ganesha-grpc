===================================================================
ganesha-export-config -- NFS Ganesha Export Configuration File
===================================================================

.. program:: ganesha-export-config


SYNOPSIS
==========================================================

    /etc/ganesha/ganesha.conf

DESCRIPTION
==========================================================

NFS-Ganesha obtains configuration data from the configuration file:

    /etc/ganesha/ganesha.conf

This file lists NFS-Ganesha Export block config options.

EXPORT PERMISSIONS
--------------------------------------------------------------------------------
These options are all "export permissions" options, and are available in
EXPORT_DEFAULTS {}, EXPORT {} and CLIENT {} blocks.

These options will all be dynamically updateable.

Access_Type(enum, default None)
    Possible values:
        None, RW, RO, MDONLY, MDONLY_RO

Protocols(enum list, default none)
    Possible values:
        3, 4, NFS3, NFS4, V3, V4, NFSv3, NFSv4, 9P

Transports(enum list, values [UDP, TCP, RDMA], default [UDP, TCP])

Anonymous_uid(anonid, range INT32_MIN to UINT32_MAX, default -2)

Anonymous_gid(anonid, range INT32_MIN to UINT32_MAX, default -2)

SecType(enum list, default [none, sys])
    Possible values:
        none, sys, krb5, krb5i, krb5p

PrivilegedPort(bool, default false)

Manage_Gids(bool, default false)

Squash(enum, default root_sqaush)
    Possible values:
        root, root_squash, rootsquash,
        rootid, root_id_squash, rootidsquash,
        all, all_squash, allsquash,
        all_anomnymous, allanonymous,
        no_root_squash, none, noidsquash

    Each line of defaults above are synonyms

**NFS_Commit(bool, default false)**

Delegations(enum, default None)
    Possible values:
        None, read, write, readwrite, r, w, rw


CLIENT {}
--------------------------------------------------------------------------------
CLIENT blocks are used in EXPORT_DEFAULTS {}, EXPORT {}, and PSEUDOFS {} blocks.

Each CLIENT block provides a list of clients and the permissions granted those
clients. These blocks form an ordered "access control list" for the export. If
no client block matches for a particular client, then the permissions in the
EXPORT {} block will be used (and if any permissions are not set between the
CLIENT and the EXPORT, then the permissions set in EXPORT_DEFAULTS will be used
and if still not set, then the code default will be used.

If an EXPORT does not have any CLIENT blocks then the list of CLIENT blocks
in EXPORT_DEFAULTS (if any) will be used. No matter the source of the CLIENT
blocks, if the client matches none, then the permissions in the EXPORT will be
applied next.

To override a restrictive default client list with "everyone" a non-empty
client list would have to be specified. Clients = "*" would do the trick.

Even when a CLIENT block matches a client, if a particular export permission
is not explicit in that CLIENT block, the permission specified in the
EXPORT block will be used, or if not specified there, from the
EXPORT_DEFAULTS block, and if not specified there, the permission will
default to the default code value noted in the permission option
descriptions above.

Note that when the CLIENT blocks are processed on config reload, a new
client access list is constructed and atomically swapped in. This allows
adding, removing, and re-arranging clients as well as changing the access
for any give client.

CLIENT blocks use all the EXPORT PERMISSIONS options (except PSEUDOFS CLIENT
blocks which are limited to the same options the PSEUDOFS block is allowed)
plus:

HA_Proxy_Protocol(enum, default any)
    Possible values:
        with_ha_proxy, without_ha_proxy, any

Clients(client list, empty)
    Client list entries can take on one of the following forms. This parameter
    may be repeated to extend the list.

        \*          Match any client
        @name       Netgroup name
        x.x.x.x/y   IPv4 network address, IPv6 addresses are also allowed
                    but the format is too complex to show here
        wildcarded  If the string contains at least one ? or *
                    character (and is not simply "*"), the string is
                    used to pattern match host names. Note that [] may
                    also be used, but the pattern MUST have at least one
                    ? or *
        hostname    Match a single client (match is by IP address, all
                    addresses returned by getaddrinfo will match, the
                    getaddrinfo call is made at config parsing time)
        IP address  Match a single client


EXPORT_DEFAULTS {}
--------------------------------------------------------------------------------
All the EXPORT PERMISSIONS options plus:

**Attr_Expiration_Time(int32, range -1 to INT32_MAX, default 60)**

CLIENT (optional)
    See the ``CLIENT  {}`` block description.
    There may be any number of these.

EXPORT_DEFAULTS { CLIENT {} }
--------------------------------------------------------------------------------
See the ``CLIENT  {}`` block description.

EXPORT {}
--------------------------------------------------------------------------------
All options below are dynamically changeable with config update unless specified
below. This block may be repeated to define multiple exports.

All the EXPORT_PERMISSIONS plus:

Export_id (required):
    An identifier for the export, must be unique and between 0 and 65535.
    If Export_Id 0 is specified, Pseudo must be the root path (/).

    Export_id is not dynamic per se, changing it essentially removes the old
    export and introduces a new export.

Path (required)
    The directory in the exported file system this export is rooted on
    (may be ignored for some FSALs). It need not be unique if Pseudo and/or Tag are specified.

    Note that if it is not unique, and the core option mount_path_pseudo
    is not set true, a v3 mount using the path will ONLY be able to
    access the first export configured. To access other exports the
    Tag option would need to be used.

    This option is NOT dynamically updateable since it fundamentally changes
    the export. To change the path exported, export_id should be changed also.

Pseudo (required v4)
    This option specifies the position in the Pseudo Filesystem this export
    occupies if this is an NFS v4 export. It must be unique. By using different
    Pseudo options, the same Path may be exported multiple times.

    This option is used to place the export within the NFS v4 Pseudo
    Filesystem. This creates a single name space for NFS v4. Clients may
    mount the root of the Pseudo Filesystem and navigate to exports.
    Note that the Path and Tag options are not at all visible to NFS v4
    clients.

    Export id 0 is automatically created to provide the root and any
    directories necessary to navigate to exports if there is no other
    export specified with Pseudo = /;. Note that if an export is
    specified with Pseudo = /;, it need not be export id 0. Specifying
    such an export with FSAL { name = PSEUDO; } may be used to create a
    Pseudo Filesystem with specific options. Such an export may also use other
    FSALs (though directories to reach exports will ONLY be
    automatically created on FSAL PSEUDO exports).

    This option is dynamically changeable and changing it will move the export
    within the pseudo filesystem. This may be disruptive to clients. Note that
    if the mount_path_pseudo NFS_CORE_PARAM option is true, the NFSv3 mount
    path will also change (that should not be disruptive to clients that have
    the export mounted).

Tag (no default)
    This option allows an alternative access for NFS v3
    mounts. The option MUST not have a leading /. Clients
    may not mount subdirectories (i.e. if Tag = foo, the
    client may not mount foo/baz). By using different
    Tag options, the same Path may be exported multiple
    times.

    This option is not dynamically updatable.

Filesystem_id(fsid, format is uint64.uint64, default unused)
    This option allows overriding the filesystem ID provided by the
    underlying filesystem. Use of this option is discouraged, It will
    not work if VFS or GPFS is exporting a filesystem that has other
    filesystems mounted on sub-directories and exported with the same
    export.

    This option is not dynamically updateable.

Read_Access_Check_Policy(enum, values [pre, post, all], default pre)
    Whether to run permission check for read before sending the read to the
    FSAL, after getting the read response from the FSAL, or both before and after.
    This allows to optimize performance for failure flow by always
    checking access before sending the read, or to optimize performance for
    success path by storing access check result in the FSAL cache during the
    read and perform the access check after the read (requires the FSAL
    implementation to support it, so should only be used with supported FSALs).
    It also allow to optimize for security by running permission check both
    before and after.

MaxRead (64*1024*1024)
    The maximum read size on this export

MaxWrite (64*1024*1024)
    The maximum write size on this export

PrefRead (64*1024*1024)
    The preferred read size on this export. Note that some older nfs
    client (e.g. libnfs 1.x) would not handle well for large preferred
    read size. If so, please try to decrease this size (usually less
    than 1M is suitable for older nfs client).

PrefWrite (64*1024*1024)
   The preferred write size on this export. Note that some older nfs
   client (e.g. libnfs 1.x) would not handle well for large preferred
   write size. If so, please try to decrease this size (usually less
   than 1M is suitable for older nfs client).

PrefReaddir (16384)
   The preferred readdir size on this export

MaxOffsetWrite (INT64_MAX)
    Maximum file offset that may be written
    Range is 512 to UINT64_MAX

MaxOffsetRead (INT64_MAX)
    Maximum file offset that may be read
    Range is 512 to UINT64_MAX

DisableReaddirPlus(bool, default false)

Trust_Readdir_Negative_Cache(bool, default false)

The following options may have limits on dynamic effect

UseCookieVerifier(bool, default true)
    Updating UseCookieVerifier while a readdir is in
    progress may result in unexpected behavior.

Disable_ACL(bool, default false)
    Disable_ACL is processed at create_export time currently
    which makes it effectively a static option.

Security_Label(bool, default false)

Attr_Expiration_Time(int32, range -1 to INT32_MAX, default 60)
    Attr_Expiration_Time is evaluated when an MDCACHE entry
    is created, so the dynamic effect of this option may
    be constrained to new entries.


CLIENT (optional)
    See the ``CLIENT  {}`` block description.
    There may be any number of these.

FSAL (required)
    See the ``EXPORT { FSAL  {} }`` block.

    The FSAL for an export can not be changed dynamically. In order to change
    the FSAL, a new export must be created.

    At this time, no FSAL actually supports any updatable options.

EXPORT { CLIENT  {} }
--------------------------------------------------------------------------------
See the ``CLIENT  {}`` block description.

EXPORT { FSAL {} }
--------------------------------------------------------------------------------
NFS-Ganesha supports the following FSALs:
**Ceph**
**Gluster**
**GPFS**
**PROXY_V3**
**PROXY_V4**
**RGW**
**VFS**
**XFS**
**LUSTRE**
**LIzardFS**
**KVSFS**

Refer to individual FSAL config file for list of config options.

The FSAL blocks generally are less updatable


.. FSAL PNFS

    Stripe_Unit(uint32, range 1024 to 1024*1024, default 8192)

    pnfs_enabled(bool, default false)

    FSAL_NULL:

    EXPORT { FSAL { FSAL {} } }
    describes the stacked FSAL's parameters

PSEUDOFS {}
--------------------------------------------------------------------------------
This block allows specifying some options for the pseudofs root export. It is
very similar to an EXPORT block, except only the following options may be
specified. CLIENT blocks may be used just like an EXPORT block, however, they
are also limited to the same options.

This is basically a shortcut rather than having to fill out options in an
EXPORT block. Note that Path, Pseudo, and Export_Id are not included as those
values will be fixed ("/" for the paths, and 0 for Export_Id). Other options
that don't make sense for the pseudofs root are also not allowed.

An empty PSEUDOFS {} block will produce the same default pseudofs root export
as generated if no pseudofs root export is otherwise specified.

This block is most useful to override a restrictive CLIENT list in
EXPORT_DEFAULTS {}.

These options will all be dynamically updateable.

Access_Type(enum, default MDONLY_RO)
    Possible values:
        None, MDONLY_RO

Transports(enum list, values [UDP, TCP, RDMA], default [TCP])

SecType(enum list, default [none, sys, krb5, krb5i, krb5p])
    Possible values:
        none, sys, krb5, krb5i, krb5p

PrivilegedPort(bool, default false)

Export_id(uint16, range 0 to UINT16_MAX, default 0)
    An identifier for the export, must be unique and between 0 and 65535.

    Export_id is not dynamic per se, changing it essentially removes the old
    export and introduces a new export.

Filesystem_id(fsid, format is uint64.uint64, default 152.152)
    Unlike standard exports, there is no underlying filesystem to get an
    ID from, so this option is important, however the default value may be
    used so it need not be specified.

    This option is not dynamically updateable.

DisableReaddirPlus(bool, default false)

Trust_Readdir_Negative_Cache(bool, default false)

The following options may have limits on dynamic effect

UseCookieVerifier(bool, default true)
    Updating UseCookieVerifier while a readdir is in
    progress may result in unexpected behavior.

PSEUDOFS { CLIENT {} }
--------------------------------------------------------------------------------
See the ``CLIENT  {}`` block description but note that beyond the Clients and
HA_Proxy_Protocol options that works as described, the other options available
are as for the PSEUDOFS {} block.

If it is desired to override a restrictive CLIENT list in EXPORT_DEFAULTS,
the following PSEUDOFS could be defined that will give all clients the
default access to the pseudofs root that otherwise would have been granted
if EXPORT_DEFAULTS was not used.

PSEUDOFS {
    CLIENT {
        Clients = *;
    }
}

DISCUSSION
==========================================================

The EXPORT blocks define the file namespaces that are served by NFS-Ganesha.

In best practice, each underlying filesystem has a single EXPORT defining how
that filesystem is to be shared, however, in some cases, it is desirable to
sub-divide a filesystem into multiple exports. The danger when this is done is
that rogue clients may be able to spoof file handles and access portions of the
filesystem not intended to be accessible to that client.

Some FSALs (currently FSAL_VFS, FSAL_GPFS, FSAL_XFS, and FSAL_LUSTRE) are built
to support nested filesystems, for example:

    /export/fs1
    /export/fs1/some/path/fs2

In this case, it is possible to create a single export that exports both
filesystems. There is a lot of complexity of what can be done there.

In discussions of filesystems, btrfs filesystems exported by FSAL_VFS may have
subvolumes. Starting in NFS-Ganesha V4.0 FSAL_VFS treats these as separate
filesystems that are integrated with all the richness of FSAL_VFS exports.

Another significant FSAL from an export point of view is FSAL_PSEUDO. This is
used to build glue exports to build the unified NFSv4 name space. This name
space may also be used by NFSv3 by setting the NFS_CORE_PARAM option:

    mount_path_pseudo = TRUE;

If no FSAL_PSEUDO export is explicitly defined, and there is no EXPORT with:

    Pseudo = "/";

NFS-Ganesha will build a FSAL_PSEUDO EXPORT with this Pseudo Path using
Export_Id = 0. This automatic EXPORT may be replaced with an explicit EXPORT
which need not have Export_Id = 0, it just must have Pseudo = "/" and
Protocols = 4.

In building the Pseudo Filesystem, there is a subtle gotcha. Since NFSv4
clients actually mount the root of the Pseudo Filesystem and then use LOOKUP
to traverse into the actual directory the sysadmin has mounted from the
client, any EXPORTs from "/" to the desired EXPORT MUST have Protocols = 4
specified either in EXPORT_DEFAULTS {}, EXPORT {}, or EXPORT { CLIENT {} }.
This is to assure that the client is allowed to traverse each EXPORT.

If Mount_Path_Pseudo = TRUE is being used and an export is desired to be
NFSv3 only, Protocols = 3 MUST be specified in the EXPORT {} block. If
Protocols is not specified in the EXPORT {} block and is only specified
in an EXPORT { CLIENT {} } block, then that export will still be mounted
in the Pseudo Filesystem but might not be traversable. Thus if the following
two filesystems are exported:

    /export/fs1
    /export/fs1/some/path/fs2

And the EXPORTs look something like this:

    EXPORT
    {
        Export_Id = 1;
        Path = /export/fs1;
        Pseudo = /export/fs1;

        FSAL
        {
            Name = VFS;
        }

        CLIENT
        {
            Clients="*";
            Protocols=3;
        }
    }

    EXPORT
    {
        Export_Id = 1;
        Path = /export/fs1/some/path/fs2;
        Pseudo = /export/fs1/some/path/fs2;

        FSAL
        {
            Name = VFS;
        }

        CLIENT
        {
            Clients="*";
            Protocols=3,4;
        }
    }

NFSv4 clients will not be able to access /export/fs1/some/path/fs2. The
correct way to accomplish this is:

    EXPORT
    {
        Export_Id = 1;
        Path = /export/fs1;
        Pseudo = /export/fs1;
        Protocols=3;

       FSAL
        {
            Name = VFS;
        }
    }

Note that an EXPORT { CLIENT {} } block is not necessary if the default export
permissions are workable.

Note that in order for an EXPORT to be usable with NSFv4 it MUST either have
Protocols = 4 specified in the EXPORT block, or the EXPORT block must not have
the Protocols option at all such that it defaults to 3,4,9P. Note though that
if it is not set and EXPORT_DEFAULTS just has Protocols = 3; then even though
the export is mounted in the Pseudo Filesystem, it will not be accessible and
the gotcha discussed above may be in play.

CONFIGURATION RELOAD
==============================
In addition to the LOG {} configuration, EXPORT {} config is the main
configuration that can be updated while NFS-Ganesha is running by issuing
a SIGHUP.

This causes all EXPORT and EXPORT_DEFAULTS blocks to be reloaded. NFS-Ganesha
V4.0 and later have some significant improvements to this since it was
introduced in NFS-Ganesha V2.4.0. V2.8.0 introduced the ability to remove
EXPORTs via SIGHUP configuration reload.

Significantly how things work now is:

On SIGHUP all the EXPORT and EXPORT_DEFAULTS blocks are re-read. There are
three conditions that may occur:

    An export may be added
    An export may be removed
    An export may be updated

A note on Export_Id and Path. These are the primary options that define an
export. If Export_Id is changed, the change is treated as a remove of the
old Export_Id and an addition of the new Export_Id. Path can not be changed
without also changing Export_Id. The Tag and Pseudo options that also contribute
to the uniqueness of an EXPORT may be changed.

Any removed exports are removed from the internal tables and if they are NFSv4
exports, unmounted from the Pseudo Filesystem, which will then be re-built as if
those exports had not been present.

Any new exports are added to the internal tables, and if the export is an NFSv4
export, they are mounted into the Pseudo Filesystem.

Any updated exports will be modified with the least disruption possible. If the
Pseduo option is changed, the export is unmounted from the Pseduo Filesystem in
it's original location, and re-mounted in it's new location. Other options are
updated atomically, though serially, so for a short period of time, the options
may be mixed between old and new. In most cases this should not cause problems.
Notably though, the CLIENT blocks are processed to form a new access control
list and that list is atomically swapped with the old list. If the Protocols
for an EXPORT are changed to include or remove NFSv4, the Pseduo Filesystem will
also be updated.

Note that there is no pause in operations other than a lock being taken when the
client list is being swapped out, however the export permissions are applied to
an operation once. Notably for NFSv4, this is on a PUTFH or LOOKUP which changes
the Current File Handle. As an example, if a write is in progress, having passed
the permission check with the previous export permissions, the write will complete
without interruption. If the write is part of an NFSv4 COMPOUND, the other
operations in that COMPOUND that operate on the same file handle will also complete
with the previous export permissions.

An update of EXPORT_DEFAULTS changes the export options atomically. These options
are only used for those options not otherwise set in an EXPORT {} or CLIENT {}
block and are applied when export permissions are evaluated when a new file handle
is encountered.

The FSAL { Name } may not be changed and FSALs offer limited support for changing
any options in the FSAL block. Some FSALs may validate and warn if any options
in the FSAL block are changed when such a change is not supported.

SEE ALSO
==============================
:doc:`ganesha-config <ganesha-config>`\(8)
:doc:`ganesha-rgw-config <ganesha-rgw-config>`\(8)
:doc:`ganesha-vfs-config <ganesha-vfs-config>`\(8)
:doc:`ganesha-lustre-config <ganesha-lustre-config>`\(8)
:doc:`ganesha-xfs-config <ganesha-xfs-config>`\(8)
:doc:`ganesha-gpfs-config <ganesha-gpfs-config>`\(8)
:doc:`ganesha-9p-config <ganesha-9p-config>`\(8)
:doc:`ganesha-proxy-config <ganesha-proxy-config>`\(8)
:doc:`ganesha-ceph-config <ganesha-ceph-config>`\(8)
