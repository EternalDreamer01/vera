#!/bin/bash

filepath="$1"
if [ -z "$filepath" ]; then
	echo "Usage: $(basename "$0") <json>" >&2
	exit 1
fi

# Yocto's built-in cve-check
if jq -e 'all(.package[] | .issue[]; has("id"))' "$filepath" &> /dev/null; then
	jq -r '
  # iterate safely over each package
  [
  .package[]
  | .name as $product
  | .version as $version
  | .layer as $ecosystem
  | (.issue // [])[]      # handle empty issue arrays
  | {
      name: $product,
      version: $version,
      cveId: .id,
      ecosystem: $ecosystem,
      state: (
		{ "Patched": "fixed",
			"Unpatched": "not-fixed",
			"Ignored": "wont-fix"
		}[.status] // "unknown"
	  ),
      cvss: (
        [ .scorev4, .scorev3, .scorev2 ]
        | map(tonumber? | select(. != 0))
        | first
      ),
      scoring_vector: (.vectorString // "")
    }
	]
' "$filepath"

# OSV-Scanner
elif jq -e 'has("results")' "$filepath" &> /dev/null; then
	jq '[
	.results[]?.packages[]? as $pkg |
	$pkg.groups[]? as $group |
	$group.aliases[]? | select(startswith("CVE-")) as $cve |
	{
		name: ($pkg.package.name // "" | gsub(":"; "-") | 
		if contains("/") then
			(split("/") | (if length >= 2 then ".../" + .[-2] + "/" + .[-1] else .[-1] end))
		else .
		end),
		version: ($pkg.package.version // "" | sub("[+\\-~].*"; "")),
		ecosystem: ($pkg.package.ecosystem // "" | gsub(":"; "-")),
		cveId: $cve,
		cvss: (
			if ($group.max_severity // "" | length) == 0 then -1
			else ($group.max_severity | tonumber)
			end
		)
	}
	]' "$filepath"

# CVE Binary Tool
elif jq -e 'all(.[]; has("cve_number"))' "$filepath" &> /dev/null; then
	jq '[
	.[] as $pkg |
	{
		name: ($pkg.product // "" | gsub(":"; "-") | 
		if contains("/") then
			(split("/") | (if length >= 2 then ".../" + .[-2] + "/" + .[-1] else .[-1] end))
		else .
		end),
		version: ($pkg.version // "" | sub("[+\\-~].*"; "")),
		vendor: ($pkg.vendor // "" | gsub(":"; "-")),
		cveId: $pkg.cve_number,
		cvss: (
			if ($pkg.score // "unknown") == "unknown" then -1
			else ($pkg.score | tonumber)
			end
		),
		scoring_vector: ($pkg.cvss_vector // "")
	}
	]' "$filepath"

# Grype
elif jq -e 'has("matches")' "$filepath" &> /dev/null; then
	jq '[
	(
		.matches[]?        | . + {__default_state: ""},
		.ignoredMatches[]? | . + {__default_state: "fixed"}
	) as $match |
	$match.matchDetails[]? as $grp |
	{
		name: ($grp.searchedBy.package.name // "" | gsub(":"; "-") | 
			if contains("/") then
				(split("/") | (if length >= 2 then ".../" + .[-2] + "/" + .[-1] else .[-1] end))
			else .
			end
		),
		version: ($grp.searchedBy.package.version // "" | sub("[+\\-~].*"; "")),
		ecosystem: (
			if $grp.searchedBy.distro? 
			then (($grp.searchedBy.distro.type // "") + "-" + ($grp.searchedBy.distro.version // "")) 
				| gsub(":"; "-")
			else null 
			end
		),
		vendor: (
			if ($grp.searchedBy.cpes[0]? | type) == "string" 
			then ($grp.searchedBy.cpes[0] | split(":")[3]) 
			else null 
			end
		),
		cveId: $match.vulnerability.id,
		cvss: (
			[
				(try $match.vulnerability.cvss[0].metrics.baseScore catch ""),
				(try $match.relatedVulnerabilities[]?.cvss[0].metrics.baseScore catch "")
			]
			| map(select(. != null))
			| max?
		),
		epss: (
			[
				($match.vulnerability.epss[]?.epss // ""),
				($match.relatedVulnerabilities[]?.epss[]?.epss // "")
			]
			| map(select(. != null))
			| max?           # pick the highest EPSS value
		),
		percentile: (
			[
				($match.vulnerability.epss[]?.percentile // ""),
				($match.relatedVulnerabilities[]?.epss[]?.percentile // "")
			]
			| map(select(. != null))
			| max?           # pick the highest percentile value
		),
		state: ($match.vulnerability.fix?.state // $match.__default_state)
	}
	]' "$filepath"

# Trivy
elif jq -e 'all(.Results[]; has("Target"))' "$filepath" &> /dev/null; then
	jq -sr '
	[ (.. | objects | select(has("VulnerabilityID"))) as $v
		| {
			cveId: $v.VulnerabilityID,
			cvss: (
				[ $v.CVSS?[]? | .V2Score?, .V3Score?, .V4Score? ]
				| map(select(. != null))
				| max // -1
			),
			name: $v.PkgName,
			version: ($v.InstalledVersion | sub("[-+~].*$"; "")),
			ecosystem: $v.DataSource.ID,
			state: ($v.Status // empty)
		}
	]
	| group_by(.cveId)
	| map(max_by(.score))
	' "$filepath"

# Vanir
elif jq -e 'all(.missing_patches[]; has("ID"))' "$filepath" &> /dev/null; then
	# echo "Detected: Vanir"
	jq -r '[
		(.covered_cves[] | {cveId: ., state: "fixed", id: null}),
		(.missing_patches[] | .ID as $id | .CVE[] | {cveId: ., state: "not-fixed", id: $id})
	]' "$filepath"

else
	echo "Error: Unexpected file format"
	exit 1
fi

