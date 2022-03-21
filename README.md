# openssl-cve
CVE info of GIT commits for OpenSSL

This repo provides CVE info of GIT commits for the [OpenSSL](https://github.com/openssl/openssl) git repo.
Such CVE info can be used by the [bomsh](https://github.com/git-bom/bomsh) tool to create the CVE database for OpenSSL,
which is then used to extract accurate CVE knowledge for OpenSSL binaries.

The following YAML format is proposed for a git commit related to CVE.

```
CVE-commit-type(Added/Fixed):
 CVE1:
  src_files:
   - file1
   - file2
 CVE2:
 CVE3:
```

Only two CVE commit types are supported: Added or Fixed.
If a git commit introduces a CVE issue, then it is a CVE-add commit.
If a git commit fixes a CVE issue, then it is CVE-fix commit.
The src_files attribute provides a list of source code files that carry/fix the CVE. Renamed files can also be included in the src_files list.
The src_files attribute is optional. When omitted, then it means all the files in the change set of the git commit.
More CVE attributes can be added in future when necessary, for example, CVE severity, affected platforms, etc.

Here are some example YAML files:

```
[yonhan@rtp-gpu-02 cveinfo_dir]$ more cveinfo.731f431.yaml 
Fixed:
 CVE-2014-0160:
  src_files:
   - ssl/d1_both.c
   - ssl/t1_lib.c
[yonhan@rtp-gpu-02 cveinfo_dir]$ more cveinfo.4817504.yaml 
Added:
 CVE-2014-0160:
  src_files:
   - ssl/d1_both.c
   - ssl/t1_lib.c
[yonhan@rtp-gpu-02 cveinfo_dir]$ 
```

The CVE info YAML filename convention is of prefix.commit-id.yaml format. The prefix is cveinfo, and commit-id is
usually the first 7 characters of the full 40-character commit ID. If the first 7 characters cannot uniquely identify
a git commit, then more characters are added until it is unique.

Annotated git tags can be used to tag the relevant CVE commits, so that the related CVE info is stored in the same OpenSSL git repo.
Or a different repo to store these CVE yaml files is perfectly fine. Run the below command to create a new git tag with the CVE YAML file as the tag message.

```
git tag -a -F cveinfo.731f431.yaml cveinfo.731f431 731f431
```

Git tags can be edited or deleted/re-added later. Also multiple git tags can be added for the same git commit, as long as tag names are unique.
For example, CVE tags use tag name of cveinfo.commit-id, while other metadata can use tag name of metadata_type.commit-id to avoid name conflicts.
So in general, this approach works for other types of metadata too.

This repo is supposed to work together with the [bomsh](https://github.com/git-bom/bomsh) tool.
All these cveinfo.*.yaml files can be downloaded and provided to the bomsh_create_cve.py script, to create the CVE database for OpenSSL.

Assume all cveinfo.*.yaml files are downloaded into the cveinfo_dir directory, then running the following command in the OpenSSL git repo will generate the OpenSSL CVE database:

```
../bomsh/scripts/bomsh_create_cve.py -vv --use_git_tags -d cveinfo_dir -j openssl_cvedb.json
```

The bomsh_create_cve.py script will extract the tag messages of cveinfo.* tags, as well as read all the cveinfo.*.yaml files in the cveinfo_dir directory, and
invoke relevant git commands to create the CVE database for OpenSSL.

Then with the help of the OpenSSL gitBOM database generated with the bomtrace2 tool,
the created CVE database can be used by the bomsh_search_cve.py script, to find out which CVEs are vulnerable for
the OpenSSL binaries, and which CVEs have been fixed.

The bomsh tool can create the gitBOM database for already released OpenSSL binaries since OpenSSL is build-reproducible.
Therefore, we should be able to get the full knowledge of CVE info for all the existing released OpenSSL Debian packages.

The cveinfo files for the heartbleed CVE-2014-0160 in 2014 and the 6 high severity CVEs for OpenSSL since 2020 have been added to this repo.

OpenSSL developers are encouraged to provide more CVE commits info, so that we can update this openssl-cve repo with more complete CVE commits info.
For all the new OpenSSL CVEs, if OpenSSL developers can also help identify the CVE-add git commit, then we can easily create the cveinfo.*.yaml files and upload to this openssl-cve repo.
And with the bomsh tool, we will be able to more accurately track CVEs for OpenSSL.

If you have any good ideas, please share with us. More people involved, more useful gitBOM/bomsh will be!
