
## Overview

VERA is a versatile and scalable tool to find CVEs, made to filter, sort and analyse CVEs reports.
Powered by :
- [Grype](https://github.com/anchore/grype)
- [CVE Binary Tool (CBT)](https://github.com/ossf/cve-bin-tool)
- [Vanir](https://github.com/google/vanir)
- [Yocto's built-in cve-check feature](https://docs.yoctoproject.org/dev/dev-manual/vulnerabilities.html)
- [CVE List V5](https://github.com/CVEProject/cvelistV5)
- [Dask](https://www.dask.org/)
- [pip-audit](https://github.com/pypa/pip-audit)
- [Docker SDK](https://docker-py.readthedocs.io/en/stable/index.html)

### Why CVE checker instead of other tools ?

- Filter and sort reports (Grype, CBT, Vanir, cve-check)
- Offline efficiency to resolve scores and indicators
- Aggregate different reports (e.g, Vanir + CBT)
- Fast checking CVE presence

*The built-in CVE scanner can rely on assumptions. You can configure the confidence via `-s/--strict` and the variable [`IMPERFECT_MATCH_VERSION_MARGIN`](.env).*

## Prerequisites

* Python 3.9+
* Docker

## Install

```sh
git clone --depth 1 --recurse-submodules -j8 https://github.com/EternalDreamer01/cve-checker.git
pip install -r requirements.txt

# Install Grype
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin

# Download Android vulnerabilities
gsutil cp gs://osv-vulnerabilities/Android/all.zip && mv all.zip android.zip
# OR
wget -O android.zip https://storage.googleapis.com/osv-vulnerabilities/Android/all.zip

# Optional autocompletion
## Bash
echo "source $PWD/src/autocompletion.sh" >> ~/.bashrc
## ZSH
echo "source $PWD/src/autocompletion.sh" >> ~/.zshrc
```
<!-- # Update and format CVEs (required)
./main.py --update
# OR
# To update completely:
./main.py --year 1999 --update -->


### Build Dockers

You may pull and build tested dockers using the command:
```sh
docker compose up --build
```

## How to use

### Scanning
```sh
# Built-in scanner - Docker
./main.py -d ubuntu:22.04 ubuntu:20.04 ...

# External scanner - Docker
./scan.sh grype ubuntu:22.04 ubuntu:20.04 ...

# External scanner - Android device/emulator
./scan.sh cbt
```

#### Import Image (VMDK, IMG or RAW)

```sh
./import-image.sh <path-to-image> <image-name>
```
__Note:__ Requires user to be in the group sudo

<!-- ### Packages through CLI
```sh
./main.py -p pkg1=1.0.0 pkg2=2.0.0 ...
```

### Packages through a file
1. Get a list of packages and save the list (in our example, we'll name it `example.csv`)
``` sh
# Debian
apt list --installed > example.csv

# Fedora
dnf list installed > example.csv
yum list installed > example.csv

# OpenSUSE
rpm -qa --queryformat '%{NAME}/now %{VERSION}\n' > example.csv
```
2. Minify the list and format it correctly:
```sh
./parse.sh minify example.csv
```
3. Perform the search:
```sh
# On a file containing a list of `package=version`
./main.py example.csv	# Only one file at a time
```

__Note:__ Take a look at the help, you might want to use `--strict` or `--year`. -->

### Inspect result
The result is saved in the file `out/os/[OS]/[VERSION]/[STATE].[SCANNER].json`. You may inspect the result using:
```sh
./parse.sh inspect android/32/raw.vanir.json    # Overview
./parse.sh inspect android/32/raw.vanir.json -A # Complete list
./parse.sh inspect android/32                   # Default to Vanir (same as above)
./parse.sh inspect android/32 --cbt             # Vanir + CBT
./parse.sh inspect android/32 --exploit         # Potential online exploits (can take a few minutes)
./parse.sh inspect android/32 --filter-out=dos,stdlib # Exclude DoS (attack type) and stdlib (product)
./parse.sh inspect android/32 --sort=epss       # Sort by EPSS

./parse.sh inspect --help # Show help
```

Show all results in a table:
```sh
./parse.sh table
```

Show one CVE information:
```sh
./parse.sh cve CVE-2022-35737 help        # Show help

./parse.sh cve CVE-2022-35737             # MITRE format full JSON data
./parse.sh cve CVE-2022-35737 .containers # MITRE format JSON path

./parse.sh cve CVE-2022-35737 description # Description
./parse.sh cve CVE-2022-35737 score       # Scores CVSS, EPSS
./parse.sh cve CVE-2022-35737 exploit     # Search online exploits or PoC


./parse.sh cve ASB-A-266433089            # Android format support
./parse.sh ASB-A-266433089                # Autodetect CVE argument
```


### Analyse OS and Verify results

#### Function presence

Check whether a function is used by some scripts or binaries/librairies:
```sh
./analyse.sh function IMAGE FUNC [DIR]
# e.g
./analyse.sh function ubuntu:20.04 EVP_PKEY_decrypt
```
__Note:__ Check for static linking only. Do not check for dynamically loaded, nor copied.

#### CVE in changelog

Check whether a CVE appear in changelog for a particular package:
```sh
./analyse.sh changelog IMAGE PKG CVE...
# e.g
./analyse.sh changelog ubuntu:20.04 openssl CVE-2024-2511
```

<!-- ## CVE/CVSS Benchmark

| OS                           | *Unknown* | LOW  | MEDIUM | HIGH | CRITICAL | TOTAL | Aff. Pkg. |
|:-                            |:-:        |:-:   |:-:     |:-:   |:-:       |:-:    |:-:        |
| Ubuntu 22.04                 | 0         | 3    | 12     | 9    | 1        | 25    | 18        |
| Ubuntu 20.04                 | 0         | 3    | 12     | 9    | 1        | 25    | 18        |
| Android 2025.08.1            | 1         | 42   | 306    | 195  | 30       | 574   | 107       |
| ROS                          | 1         | 40   | 345    | 603  | 46       | 1035  | 92        |
| VxWorks 7                    | 1         | 16   | 54     | 34   | 4        | 109   | 42        |
| VxWorks 7 ROS2               | 1         | 22   | 74     | 52   | 4        | 153   | 66        |
| TeslaOS                      | 0         | 20   | 46     | 35   | 8        | 109   | 34        |
| QNX Neutrino                 | 1         | 24   | 94     | 91   | 19       | 229   | 65        |
| Automotive Grade Linux (AGL) | 0         | 0    | 1      | 3    | 0        | 4     | 3         |
|   IVI Demo Qt                | 0         | 1    | 1      | 3    | 0        | 5     | 4         |
| Automotive SIG               | 0         | 1    | 14     | 11   | 0        | 26    | 9         |
| Eclipse S-CORE               | 0         | 1    | 0      | 0    | 0        | 1     | 1         |
| Zephyr                       | 0         | 72   | 91     | 66   | 4        | 233   | 67        |

*Raw*


| OS                           | *Unknown* | LOW  | MEDIUM | HIGH | CRITICAL | TOTAL | Aff. Pkg. |
|:-                            |:-:        |:-:   |:-:     |:-:   |:-:       |:-:    |:-:        |
| Ubuntu 22.04                 | 0         | 3    | 12     | 9    | 1        | 25    | 18        |
| Ubuntu 20.04                 | 0         | 3    | 12     | 9    | 1        | 25    | 18        |
| Android 2025.08.1            | 1         | 37   | 240    | 91   | 8        | 377   | 90        |
| ROS                          | 1         | 40   | 321    | 603  | 46       | 1011  | 91        |
| VxWorks 7                    | 1         | 16   | 42     | 26   | 3        | 88    | 40        |
| VxWorks 7 ROS2               | 1         | 22   | 62     | 44   | 3        | 132   | 64        |
| TeslaOS                      | 0         | 20   | 46     | 34   | 8        | 108   | 34        |
| QNX Neutrino                 | 1         | 24   | 94     | 90   | 19       | 228   | 65        |
| Automotive SIG               | 0         | 1    | 14     | 11   | 0        | 26    | 9         |
| Eclipse S-CORE               | 0         | 1    | 0      | 0    | 0        | 1     | 1         |
| Zephyr                       | 0         | 72   | 91     | 66   | 4        | 233   | 67        |

*Upgraded*


| Framework                      | Version $^1$           | Release $^2$   | *Unknown* | LOW  | MEDIUM | HIGH | CRITICAL | TOTAL | Aff. Pkg. |
|:-                              |:-                      |:-              |:-:        |:-:   |:-:     |:-:   |:-:       |:-:    |:-:        |
| NVIDIA CUDA                    | 11.4.3 /8.9            |                | 0         | 5    | 19     | 14   | 2        | 40    | 40        |


### OS Details

| OS                             | Version $^1$           | Release $^2$   | Undelying OS version and release | 
|:-                              |:-                      |:-              |:-                                |
| Ubuntu                         | 22.04                  | jammy          |
|                                | 20.04                  | focal          |
| Android                        | 2025.08.1              | jammy          |
| [ROS][1009]                    |                        | humble         | Ubuntu 22.04 - jammy             |
| [VxWorks][1001]                | 7                      | humble         | Ubuntu 22.04 - jammy             |
|                                | 7 ROS2                 | humble         | Ubuntu 22.04 - jammy             |
| [TeslaOS][1002]                | amd-5.4(.265)          | focal          | Ubuntu 20.04 - focal             |
| [QNX Neutrino][1003]           | 8.0                    | focal          | Ubuntu 20.04 - focal             |
| [Automotive Grade Linux][1004] | agl-ivi-image 20.90.0  | unagi          | N/A (Yocto)                      |
| [Automotive SIG][1005]         | 9                      | /              | RedHat 9                         |

[1001]: https://github.com/Wind-River/vxworks7-ros2-build "VxWorks7 ROS2"
[1002]: https://github.com/teslamotors/linux "TeslaOS"
[1003]: https://ros2-qnx-documentation.readthedocs.io/en/galactic/docker_development.html "QNX"
[1004]: https://download.automotivelinux.org/AGL/release/salmon/latest/qemux86-64/deploy/images/qemux86-64/ "Automotive Grade Linux - source"
[1005]: https://autosd.sig.centos.org/AutoSD-9/nightly/raw-images/ "Automotive SIG - source"
[1009]: https://docs.ros.org/en/rolling/Tutorials/Advanced/Security/Deployment-Guidelines.html#generating-the-docker-image "ROS2" -->


<!-- ### Comparison

| Tool			| Free API	| Offline	| Unlimited		| Recorded CVEs/EUVDs	| Number of products	| Handle multiple products	| Does NOT need CPE	| Handle versions	| Accuracy |
|:-			|:-:		|:-:		|-:				|:-						|:-						|:-:						|:-:				|:-:				|:-:| 
| [ENISA][0]		| ️✅		| ✕			| ✅ $^2$		| 260k					| ?					| ✕							| ✅					| ✅					| 
| [NIST][1]			| ️✅		| ✕			| 10/min $^2$		| 287k					| 141k					| ✕							| ✕					| ✅					| 
| [RedHat][2]		| ️✅		| ✕			| ️✅ $^2$		| 40k $^2$						| ?			| ✕							| ✅					| ✕					|
| [CVEdetails][3]	| ️✅		| ✕			| 10/min $^2$		| 220k						| 178k				| ✕							| ✕					| ✅					|
| [Snyk][4]			| ✕			| ✕			| [2k/min][402]	| 100k $^2$						| ?						| ✅ \*								| ✅					| ✅					|
| [OpenCVE][5]		| ✅ $^1$	| ✕			| 60/h $^3$		| 302k					| ?						| ✕							| ✕					| ✕					|
| [cve-search][6]	| ️✅		| ️✅		| ️✅			| 287k (NIST)						| 141k (NIST)						| ✕							| ✅					| ✅					| 
| [CVE Binary Tool][7]	| ️✅	| ️✅		| ️✅			| ? (RedHat) 						| 410								| ✅ \*\*					| ✅					| ✅					|
| [pip-audit][8]	| ️✅		| ️✅		| ️✅			| ? (RedHat) 						| ? (RedHat)						| ✅ \*\*\*					| ✅					| ✅					|
| CVE Checker		| ️✅		| ️✅		| ️✅			| 145k					| 61k					| ✅						| ✅					| ✅					|

[0]: https://euvd.enisa.europa.eu/apidoc "ENISA"
[1]: https://nvd.nist.gov/developers/vulnerabilities "NIST"
[2]: https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index "RedHat"
[3]: https://www.cvedetails.com/api/v1/swagger-ui/#/vuln/__user%2Fvuln%2Flist-by-vpv "CVEdetails"
[4]: https://docs.snyk.io/snyk-api/reference/collection "Snyk"
[5]: https://docs.opencve.io/api/ "OpenCVE"
[6]: https://github.com/cve-search/cve-search "cve-search"
[7]: https://github.com/intel/cve-bin-tool "CVE Binary Tool"
[8]: https://github.com/pypa/pip-audit "pip-audit"

[402]: https://docs.snyk.io/snyk-api/v1-api#rate-limiting "Snyk Rate Limit"

- $^1$ Paid services availables
- $^2$ Testing-based
- $^3$ For the Free plan (Organization > Billing)
---
- \* Analyse [used packages](https://docs.snyk.io/supported-languages-package-managers-and-frameworks) within a source code or Docker
- \*\* Analyse files in a directory
- \*\*\* Analyse dependencies within current environment (or project eventually)

#### Notes
- Total number of recorded CVE since 1999 is **299k**
```sh
find cvelistV5/cves/ -type f -name "CVE-*.json" | wc -l
```

- Total number of recorded products by MITRE since 1999 is **56k**
```sh
# Can take a few minutes
jq '"\(try .containers.cna.affected.[] | .vendor +":"+ .product)"' < $(find cvelistV5/cves/ -type f -name "CVE-*.json") | grep -v ':n/a"' | sort -u | wc -l
```

- Total number of recorded products by NIST is **141k**
```sh
wc -l src/asset/cpe.csv
```
- Total number of formatted products by our solution is 48k:
```sh
jq length cves.json
```
- Total number of formatted CVEs by our solution is 58k:
```sh
jq '.[][].cveId' cves.json | sort -u | wc -l
```
- Total number of identified CVEs within tested OS:
```sh
find out/os/ -name "*.json" -exec jq 'try .[].cveId' {} + | cut '-d"' -f2 | sort -u | grep -v null | wc -l
```

## How does it work

0. During update (`-u/--update`), CVEs are rewritten in a standard format, so they can be parsed and understood efficiently later.

1. CVEs since specifified year (default is since 2017) are all loaded into memory,
1. Make a list of delayed tasks for products to test following [assumptions](#assumptions)
1. Launch tasks looking for CVEs:
    1. Find match between the product and a specific wanted one
    1. If it matches, parse the affected versions

### Assumptions

1. The real package name can be a substring suffixed by `-`, ` ` (space) or `_` + something (e.g `xz-utils` is `xz`)
1. The real package name can be prefixed by `python[3]-`, `golang-[*]-` `ros-[*]-`, `r-[*]-`, `ruby-[*]-`, or `linux-[*]-` (e.g `python3-dask` is `dask`)
1. In case the product don't perfectly match (either because it's the result of splits, or by the prefix removal), check if the versions' major are too wide (default maximum margin is 40% difference)
1. The package name can omit `-` or other special characters (e.g `7-zip` is the same as `7zip`),
1. The field `product` can contain the vendor (e.g `gnu/wget`)
1. The field `product` can contain multiple products, separated by `,`, `;` or `:`

## FAQ

### Why searching for CVEs since 2017 by default ?
CVEs have a less standardized format before 2017. `affected_packages` don't contain `vendor`, `product` or `version`, making them harder to parse.
You may specify a different year using `-y/--year` below 2017, but it might not be meaningful.

### Why NIST's recorded products (CPE) is higher than products recorded by MITRE since 1999 ?
2 reasons:
- NIST's list contains duplicates
- MITRE's recorded CVE isn't always well formatted, especially before 2017. There are 139k CVEs with no correctly defined product (defined as `n/a`)
 -->

## TODO

<!-- 
- [PLY](https://ply.readthedocs.io/en/latest/ply.html) to parse language correctly.

- Different levels of strictness:

	0. Flex
	0. Check vendor flexibly and description WITH OR WITHOUT eventual 2nd part (e.g `ros-humble` is ROS, `Windows Server` remains as it is). Looking for the prefix anywhere
		* Determine if the 2nd part is a release or part of the name
	0. Product must exactly match, or Vendor must exactly match prefix.
	0. Product must exactly match

- Implicit greaterThanOrEqual on list >= 2 items

- Handle Venv

- Use x_legacyV4Record

- Platform and architecture

- Confidence score, based on:
	- vendor: debian, gnu, linux, *same as product* etc.
	- strictness/splitting

- Filter for SDV on `inspect`: commands -->
- Parse and display prerequisites on `inspect`: SELinux, symbol
- Add PoC/potential exploit based on the string "PoC" in GitHub/Gitlab issues from references

- Frameworks to test:
	- CUDA 11.4, 11.8, 12.4, latest
	- TensorRT: https://hub.docker.com/r/openeuler/tensorrt
	- OpenVINO: https://hub.docker.com/r/openvino/ubuntu24_runtime
	- OpenCV: https://hub.docker.com/r/gocv/opencv
