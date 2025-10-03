# SLSA End-to-End With AMPEL & Friends

This post illustrates a SLSA end-to-end implementation using
[🔴🟡🟢 AMPEL](https://github.com/carabiner-dev/ampel), the Amazing Multipurpose
Policy Engine (and L) and other tools in the supply chain ecosystem to generate
and verify attested data leveraging VSA receipts of each verification step.

Most of the policies in this case study leverage AMPEL's community polcies
repository.

### Requirements

This example runs through the
[release workflow in the demo repository](https://github.com/carabiner-dev/demo-slsa-e2e/blob/main/.github/workflows/release.yaml).
If you want to try running the verification steps yourself, download
[the latest AMPEL binary](https://github.com/carabiner-dev/ampel/releases/latest).
We also recommend downloading [bnd](https://github.com/carabiner-dev/bnd) to
inspect the generated attestations.

We'll walk through the steps in the workflow. When it runs all the verification
results are displayed on the run page ([example](https://github.com/carabiner-dev/demo-slsa-e2e/actions/runs/18217437602))
if you look at the execution output ([example](https://github.com/carabiner-dev/demo-slsa-e2e/actions/runs/18217437602/job/51869676510)),
you'll notice that steps that involve AMPEL are marked with its traffic
lights (🔴🟡🟢), those that use `bnd` are marked with its pretzel logo (🥨).

## Meet the Fritoto Project

This walkthrough will analyze how the Fritoto project releases secure binaries.
Fritoto (a play on Friday \+ In-toto) is a utility that generates attestations
that inform if a software piece was built on a Friday. Why? Well… you don’t
deploy on Fridays, right? Fritoto’s attestations let you write policies to
prevent shipping software laced with Fridayness.

(Note that Fritoto is a joke project, but it is fully functional if you want to
attest those cursed EoW builds).

As a security tool, Fritoto has implemented a secure build process, starting with
a hardened revision history and extending to the secure execution of its binaries.

Let’s inspect their hardened supply chain security architecture!

## It all starts at the source…

All security guardrails are worthless if attackers can inject malicious code into
the codebase. To ensure all changes going into the codebase are properly vetted,
the Fritoto team have secured their git repository with
[`sourcetool`](https://github.com/slsa-framework/source-tool), the SLSA Source
Track CLI.

The SLSA Source tools allowed the project to onboard its repository in minutes,
hardening the revision history and setting up tools to continuously check the
repository security controls are properly set. Once the SLSA Source workflows are
in place, each commit receives its own SLSA Source attestations, confirming
that all changes have been merged while the repository controls were in place.

By checking the SLSA Source attestations, Fritoto makes sure all builds are run
on a commit that is guaranteed to be preceded by others merged through the proper
mechanisms.

In their release process, before anything goes on, Fritoto leverages AMPEL to
enforce a policy that verifies the build point’s source attestations:

```yaml
- name: 🔴🟡🟢 Verify Build Point Commit to be SLSA Source Level 3+
  uses: carabiner-dev/actions/ampel/verify@HEAD
  with:
    subject: "sha1:${{ github.sha }}"
    policy: "git+https://github.com/carabiner-dev/policies#vsa/slsa-source-level1.json"
    collector: "note:https://github.com/${{ github.repository }}@${{ github.sha }}"
    signer: "sigstore::https://token.actions.githubusercontent.com::https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main"
    attest: false

- name: 🥨 Export source attestations
  id: export-source-attestations
  run: |
    bnd read note:${{ github.repository }}@${{ github.sha }} --jsonl >> .attestations/attestations.bundle.jsonl
    echo "" >> .attestations/attestations.bundle.jsonl

```

AMPEL pulls the commit’s VSA (Verification Summary Attestation) from the commit
notes and verifies that the repository had Source Level 3 protections in place,
ensuring no rogue commits altered the code base. Using bnd, we extract the
attestations and add them to a jsonl bundle where we'll collect all the build
process security metadata.

## No Trust, No Go

Now that the source is trusted, the Fritoto release process checks its builder.
It uses [Chainguard’s Go image](https://images.chainguard.dev/directory/image/go/overview)
to build binaries for various platforms. This image ships with some attestations
already built in, making it is easy to verify it with AMPEL. We will leverage
its SLSA Build provenance attestation to make sure the Go compiler comes from
[Chainguard’s SLSA3 build system](https://edu.chainguard.dev/compliance/slsa/slsa-chainguard/).

To verify it, AMPEL pulls the provenance attestations attached to the image using
its `coci` (Cosign/OCI) collector driver, and runs them through tge the builder
PolicySet. AMPEL will also generate a VSA capturing the results of the verification.
We’ll also save it for later.

```yaml
- name: 🔴🟡🟢 Verify Builder Image  
  uses: carabiner-dev/actions/ampel/verify@HEAD  
  with:  
    # The verification subjest: The image digest  
    subject: "${{ steps.digests.outputs.builder }}"  
    # Use the modified policy set  
    policy: "policies/verify-builder-image-slsa3.set.json"  
    # Collect builder attestations attached to the image  
    collector: "coci:cgr.dev/chainguard/go"  
    # We don't specify the signer here as it's baked in the policy code, but
    # we could do it:
    # signer: "sigstore::https://token.actions.githubusercontent.com::https://github.com/slsa-framework/source-actions/.github/workflows/compute\_slsa\_source.ml@refs/eads/main"
    attest: false  
```  

[Check the source](https://github.com/carabiner-dev/demo-slsa-e2e/blob/cb5a32d292d1222e8d55a5d0d0585e2da0efe7a1/.github/workflows/release.yaml#L98-L109).

### The Build Image PolicySet

A PolicySet is a group of policies that AMPEL applies together. Fritoto’s 
[build image PolicySet](https://github.com/carabiner-dev/demo-slsa-e2e/blob/main/policies/verify-builder-image-slsa3.set.json)
performs the [verifications suggested in the SLSA spec](https://slsa.dev/spec/v1.0/verifying-artifacts) by reusing three
policies from AMPEL’s community repository:

```json
   "policies": \[  
        {  
            "id": "slsa-builder-id",  
            "source": {  
                "location": { "uri": "git+https://github.com/carabiner-dev/policies\#slsa/slsa-builder-id.json" }  
            },  
            "meta": { "controls": \[ { "framework": "SLSA", "class": "BUILD", "id": "LEVEL\_3" } \] }  
        },  
        {  
            "id": "slsa-build-type",  
            "source": {  
                "location": { "uri": "git+https://github.com/carabiner-dev/policies\#slsa/slsa-build-type.json" }  
            },  
            "meta": { "controls": \[ { "framework": "SLSA", "class": "BUILD", "id": "LEVEL\_3" } \] }  
        },  
        {  
            "id": "slsa-build-point",  
            "source": {  
                "location": { "uri": "git+https://github.com/carabiner-dev/policies\#slsa/slsa-build-point.json" }  
            },  
            "meta": {  
                "controls": \[ { "framework": "SLSA", "class": "BUILD", "id": "LEVEL\_3" } \],  
                "enforce": "OFF"  
            }  
        }  
    \]
```

The policies are referenced remotely but if you look at each policy, you’ll see
that they
[verify the build type](https://github.com/carabiner-dev/policies/blob/main/slsa/slsa-build-type.json),
[look for the expected builder ID](https://github.com/carabiner-dev/policies/blob/main/slsa/slsa-builder-id.json), and
[verify the build point](https://github.com/carabiner-dev/policies/blob/main/slsa/slsa-build-point.json) (although this one is not enforced in the policy set for now, as the data seems to be missing from the image provenance attestation). The policy
set defines the contextual data required by each policy. Also, you’ll notice that
the signer identities are verified and
["baked" into the policyset code](https://github.com/carabiner-dev/demo-slsa-e2e/blob/cb5a32d292d1222e8d55a5d0d0585e2da0efe7a1/policies/verify-builder-image-slsa3.set.json#L24-L32):

```json
  "identities": [
      {  
          "sigstore": {  
              "issuer": "https://token.actions.githubusercontent.com",  
              "identity": "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"  
          }  
      }  
  ]
```

By codifying the signer identities and contextual values in the policy, you can
make them immutable if you sign the policy.

## Moaar Data!

As part of their build process, the Fritoto builder creates additional attestations
to ensure the build is safe to ship and increase the transparency of the released
assets. All of these additional attestations will describe data about the build
commit, they will be collected and checked before releasing the binaries. The
example workflow goes through these steps linearly for clarity’s sake.

### SBOM

First, to keep track of all dependencies, the build process builds an SPDX
Software Build of Materials. The release workflow uses Carabiner's
[unpack](https://github.com/carabiner-dev/unpack) as it generates an attested
SBOM natively but you can use any SBOM generator such as Syft or Trivy and tie
the SBOM to the commit in an attestation with `bnd predicate`.

### Checking for Vulnerabilities (and dealing with them)

Next, the build process generates an attestation of an OSV vulnerability scan.
It is wrapped and signed. But alas! OSV scanner found that the project is
susceptible to CVE-2020-8911 and CVE-2020-8912 (BTW, we've 
[injected these vulns](https://github.com/carabiner-dev/demo-slsa-e2e/blob/cb5a32d292d1222e8d55a5d0d0585e2da0efe7a1/go.mod#L5-L6)
on purpose for this demo 😇). Further down, AMPEL will gate on any vulnerabilities
before shipping the binaries, so we need to address them or the policy will fail.
How? Well, we VEX!

As these CVEs are [known not to be exploitable in Fritoto](https://github.com/carabiner-dev/demo-slsa-e2e/blob/cb5a32d292d1222e8d55a5d0d0585e2da0efe7a1/main.go#L16-L21),
the release engineers issue two OpenVEX attestations assessing the project as
[`not_affected`](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels)
by them. They do this using [vexctl](https://github.com/openvex/vexctl) the
OpenVEX CLI that manages VEX documents, and then signing them into attestations
using bnd.

### Show me Those Tests!

Next up, Fritoto leverages [beaker](https://github.com/carabiner-dev/beaker),
an experimental tool from Carabiner Systems that runs your project’s tests and
generates a standard
[test-results](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
attestation from the tests run. Again, this statement will describe the test run
at the specific build point, that is, it will have the commit’s sha as its subject.

## Build that Castle!

It is time to run the build. But before doing so, we need to verify that all the
attested data checks out. AMPEL will gate the build by
[applying a preflight PolicySet](https://github.com/carabiner-dev/demo-slsa-e2e/blob/main/policies/release-preflight.json)
to all the collected attestations, stopping the workflow if anything goes wrong.

```yaml
  # Gate the build enforcing the preflight policy  
  - name: 🔴🟡🟢 Run Release Pre-flight Verification  
    uses: carabiner-dev/actions/ampel/verify@HEAD  
    with:  
      subject: "sha1:${{ github.sha }}"  
      policy: "git+https://github.com/${{ github.repository }}\#policies/release-preflight.json"  
      collector: "jsonl:.attestations/attestations.bundle.jsonl"  
      attest: false  
```

In this case, AMPEL collects the attestations using its jsonl collector on the
file that the release process has been assembling on each step. You'll notice
that the policy is referenced remotely; this ensures that the policy code cannot
be changed during the build process. Note that while policies can be signed, we
are using them unsigned here to see their code more easily.

We won't go into the policy details, but you can check the policy set code and
see that it reuses three community polices that: check that:
1\) [The SBOM was generated](https://github.com/carabiner-dev/policies/blob/main/sbom/sbom-exists.json),
2\) [All unit tests passed](https://github.com/carabiner-dev/policies/blob/main/test-results/tests-pass.json),
and 3\) [There are no vulnerabilities present](https://github.com/carabiner-dev/policies/blob/main/openvex/no-exploitable-vulns-osv.json).

As we mentioned before, the scan returned two CVEs, but thanks to the OpenVEX
attestations, the release is allowed to run because the
[non-exploitable vulnerabilities policy](https://github.com/carabiner-dev/policies/blob/main/openvex/no-exploitable-vulns-osv.json)
leverages the
[VEX transformer](https://github.com/carabiner-dev/policies/blob/0816f604293d448e7ce0800d82134c15bf9bb3dc/openvex/no-exploitable-vulns-osv.json#L7-L9)
in AMPEL. This transformer reads attested VEX statements and suppresses any
non-exploitable vulnerabilities according to the signed VEX data.

Next, the workflow runs the build using the verified image. After running the
build script, we’ll have the binaries of the Fritoto attester for various
platforms ready to ship.

## Generating SLSA Build Provenance

After the build is done, the workflow will assemble the binaries’ SLSA Build
provenance attestation using the
[Kubernetes Tejolote attester](https://github.com/kubernetes-sigs/tejolote).
Tejolote queries the build system and extracts data about the jobs that produced
the artifacts, their build environment, and their configuration:

```yaml
  - name: 🌶️ Generate SLSA Provenance Attestation  
    id: tejolote
    run: |  
      # Generate the provenance attestation with the Tejolote attester  
      tejolote attest github://${{github.repository}}/"${GITHUB_RUN_ID}" \
        --artifacts file:$(pwd)/bin/ \
        --output .attestations/provenance.json \--slsa="1.0" \
        --vcs-url=cgr.dev/chainguard/go@${{ steps.digests.outputs.builder }}

      # Sign the provenance attestation  
      bnd statement .attestations/provenance.json >> .attestations/attestations.bundle.jsonl  
      echo "" >> .attestations/attestations.bundle.jsonl

```

This step adds the provenance attestation to the same jsonl bundle with the
rest of the attestations.

Note that for demonstration purposes, the build process is running Tejolote in the same job, which is not ideal. Tejolote is designed to run outside of the workflow; it observes the build system running and attests when the build is done. But for the demo, it will do for now.

## Final Check Before Release

Finally, Fritoto performs a SLSA Build and Source verification on the built binaries
to ensure everything ties together. To spare downstream consumers from doing the
same heavy checks, the project will issue separate VSAs, one for each binary, which
can be later used to check that every verification up to this point actually took
place and the results were as expected.

Here, the workflow runs the ampel binary for each binary and collects the
resulting VSAs:

```yaml
  - name: 🔴🟡🟢 Verify All Artifacts and Generate VSAs  
    id: artifact-vsas  
    run: |  
            echo "$HOME/.carabiner/bin" >> $GITHUB_PATH  
            ls \-l bin/  
            for binfile in $(ls bin/\*);   
              do ampel verify "$binfile" \
                --policy "git+https://github.com/${{ github.repository }}#policies/release-preflight-slsa-build.json" \
                --collector jsonl:.attestations/attestations.bundle.jsonl \
                --attest-results --attest-format=vsa --results-path=vsa.tmp.json \
                --format=html >> $GITHUB_STEP_SUMMARY;

              bnd statement vsa.tmp.json >> .attestations/attestations.bundle.jsonl;  
              echo "" >> .attestations/attestations.bundle.jsonl;  
              rm -f vsa.tmp.json;  
            done  
```

### The Pre-Release PolicySet

The pre-release policy set does the following checks:

1) The SLSA Build verification of the binaries themselves as recommended on the spec.
2) Verifies the dependency VSAs produced from the previous verifications, namely:
   1) That the build image is `SLSA_BUILD_LEVEL3`
   2) That the git commit used as build point is `SLSA_SOURCE_1`

The advantage of verifying the VSAs is that we don’t have to do all the checks
again.

What makes this step special is that we will mix attestations that describe
different components of the build process: the built binaries (from the build
provenance), the git commit (the source VSAs), and the builder image (from the
VSAs generated by AMPEL when it verified it). Now, the new VSAs we are about to
produce will have each platform binary as their subject, so how do we check
them all from a single policy set? The answer: Form a chain.

### Chaining Subjects

To support this scenario, AMPEL supports the notion of chained subjects. The
chain connects an initial subject (the Fritoto binary) to another in its SDLC
such as the build image or the source commit. To connect them in the policy, the
Fritoto team wrote selectors that act as carabiners clipping the binary to both
the image and its build commit by extracting data from the build provenance.
Here is an example, shortened for illustration:

```json
 "chain": [  
    {  
        "predicate": {  
            "type": "https://slsa.dev/provenance/v1",  
            "selector": "predicates[0].data.buildDefinition.resolvedDependencies.map(dep, dep.uri.startsWith(context.buildPointRepo + '@'), dep)[0]"  
        }  
    }  
],

```  

This selector code extracts the URI from the `resolvedDependencies` field in the
build provenance when it matches the repository name. AMPEL then synthesizes from it
a new in-toto subject and re-fetches the new subject's attestations, evaluating
the policy on the commit, instead of the binary.

### Attesting the Verification

After running the prerelease policy, AMPEL generates a SLSA VSA attesting to
everything we’ve seen so far. Here is an example:

```json
{  
  "predicateType": "https://slsa.dev/verification_summary/v1",  
  "predicate": {  
    "dependencyLevels": {  
      "SLSA_BUILD_LEVEL_3": "1",  
      "SLSA_SOURCE_1": "1"  
    },  
    "inputAttestations": [
      {  
        "digest": {  
          "sha256": "91e6462a44f09ed64a116366309df93fdc73479e6efac4b8df5977db5211f483",  
          "sha512": "a267338f5793f40342753bd0907bd1f6f70e9c23fd9354f549015a8da585127051138d2c08de704289e727fe12a6668e4b9e9c15bc9899e06a9a47d71f8d48c2"  
        },  
        "uri": "jsonl:.attestations/attestations.bundle.jsonl#7"
      },  
      {  
        "digest": {  
          "sha256": "1986b7579ab97ed99ac26e9e60c071226cf9dc14426f97c7aca07622ade18fb6",  
          "sha512": "b6ae07bd5419e174b2435fd22e8e6f0d07e5bd8be5b8ecba92fda674db283b072a964b5642ccc3caf2d063b5024eda496b0c4475e8a61aa3adf014e8ec179967"  
        },  
        "uri": "jsonl:.attestations/attestations.bundle.jsonl#6"  
      },  
      {  
        "digest": {  
          "sha256": "677d5750e149f926c22fa1acd729b82904c0651e3cbf07440f41e7c5c124a99d",  
          "sha512": "ee2907d53b672e8ce69247fdf3ef4c8fadb749260c004361ffc55c9a76dbd716430d2caa94e6813019c954202e8dfd727733a2bc03359a57647db05ac66939e7"  
        },  
        "uri": "jsonl:.attestations/attestations.bundle.jsonl#1"  
      },  
      {  
        "digest": {  
          "sha256": "d9e62d33953cd5a64bbd8cce6f9c2ba4af7e4c7041ff80f3e216092c55bd9aa1",  
          "sha512": "ba3404aa79483e56ed971d8e882a96471e47854e189d96581b7b08d089a33e3bb87a44c9f4db77998fb9b152239f6f0231b18600bac94315a0187da1248c219b"  
        },  
        "uri": "jsonl:.attestations/attestations.bundle.jsonl#3"  
      }  
    ],  
    "policy": {  
      "digest": {  
        "sha256": "62220a01aa36267f6f82d2204d9021fdc1db3ee7e7dc03b562e62ec462718136",  
        "sha512": "85efcb43985589a6557adff865f4950b6b20d60f12e4c22a289432d3dfe87ff49bf1d61e01adb6e445b6f0c5d865381d9616b202f92143177180a1df5efcfa2c"  
      }  
    },  
    "resourceUri": "bin/fritoto-linux-amd64",  
    "slsaVersion": "1.1",  
    "timeVerified": "2025-10-03T05:25:08.324338730Z",  
    "verificationResult": "PASSED",  
    "verifiedLevels": [
      "SLSA_BUILD_LEVEL_3"
    ],
    "verifier": {  
      "id": "https://carabiner.dev/ampel@v1"  
    }  
  },
  "_type": "https://in-toto.io/Statement/v1",  
  "subject": [
    {
      "name": "fritoto-linux-amd64",  
      "uri": "bin/fritoto-linux-amd64",  
      "digest": {  
        "sha256": "21b3129c3707d19b79596b9acb75fd7d245675bec9d1cede3d08250b2ddb1f6e",  
        "sha512": "26fe589a09d779833adb20b32230e6be9b0540db290bd148026fd814573c05988c43e02457b7245f70c3477ed706bacc5bf9b820dcde3eab0ff39a4c0e4b50b5"
      }
    }
  ]
}  
```

Notice in the VSA how the subject is the binary and how its `SLSA_BUILD_3` level
is recorded but also the verified levels of its dependencies. The important parts
in this document are:

- The verifier ([https://carabiner.dev/ampel@v1](https://carabiner.dev/ampel@v1)) that tells you what tool performed the verification  
- The subject (the fritoto-linux-amd64 binary)  
- The verification result (`PASSED`)  
- The verified levels of the binary (`SLSA_BUILD_LEVEL_3`)  
- The verified SLSA levels of the dependencies (`dependencyLevels`):  
  - One `SLSA_BUILD_LEVEL_3` (the go container image)
  - One `SLSA_SOURCE_1` (the build point commit, protected with the SLSA source tools)

This VSA can be used to communicate to users the verifications performed on the
binaries, to act as guarantees that the released assets were built in a secure
environment.

## End User Verification

Now that the Fritoto project has produced VSAs for all its binaries, the project
users should be able to use them! Especially since Fritoto is a “security”
(wink wink) tool that runs in CI. So how do they verify the executables?

To verify the binaries, users only need the
[latest release of AMPEL](https://github.com/carabiner-dev/ampel/releases/latest)
installed. AMPEL can check the binary directly or verify its hash (as published
on the project's
[release page](https://github.com/carabiner-dev/demo-slsa-e2e/releases/latest)).
The Fritoto team has published a
[policy to verify the project'’'s binaries](https://github.com/carabiner-dev/demo-slsa-e2e/blob/main/policies/check-artifacts.json).
You don’t need to download the policy or the attestations; AMPEL can fetch them
for you when it needs them.

```bash
ampel verify sha256:b2f66926949aef30bede58144b797b763fed2d00c75a58a246814a5e65acec55 \
      --policy "git+https://github.com/carabiner-dev/demo-slsa-e2e\#policies/check-artifacts.json" \
      --collector release:carabiner-dev/demo-slsa-e2e@v0.1.1  
```

The results in the terminal show the checks performed on the VSA with their
respective verification results:

```
+--------------------------------------------------------------------------------------------------------------------+  
| ⬤⬤⬤AMPEL: Evaluation Results                                                                                       |  
+-------------------------+--------------------------+--------+------------------------------------------------------+  
| PolicySet               | fritoto-artifacts-verify | Date   | 2025-10-03 11:45:39.149795 -0600 CST                 |  
+-------------------------+--------------------------+--------+------------------------------------------------------+  
| Status: ● PASS          | Subject                  | - sha256:b2f66926949aef30bede58144b797b76...                  |  
+-------------------------+--------------------------+--------+------------------------------------------------------+  
| Policy                  | Controls                 | Status | Details                                              |  
+-------------------------+--------------------------+--------+------------------------------------------------------+  
| slsa-build-level-3      | BUILD-LEVEL_3            | ● PASS | VSA attesting a SLSA_BUILD_3 compliance verification |  
| slsa-build-deps-level-3 | BUILD-LEVEL_3            | ● PASS | All verified dependencies are SLSA_BUILD_LEVEL_3+    |  
| vsa-verify-verifier     | -                        | ● PASS | Attestation was issued by trusted verifier           |  
+-------------------------+--------------------------+--------+------------------------------------------------------+  
```

### Checking the Attestation Bundle

The Fritoto project releases a lot of security metadata along with its binaries. The attestations bundle contains 17
statements, if you want to see what is in there, you can use
[bnd, the attestations multitool](https://github.com/carabiner-dev/bnd):

```bash  
bnd inspect attestations.bundle.jsonl  
```

This command displays details of the included attestations: who signed them, their
subjects, and their type. Using bnd you can extract the attestations or view the
predicates.

Exploring the data should give you an idea of the kinds of policies that can be
written, and since all the tools used here are open source, you can use them in
your projects too! If you write something cool, consider contributing it to
AMPEL’s community policies for others to reuse.

## Conclusion

This case study went through the basic steps of a secure build leveraging the SLSA
model:

1. We checked the source code attestations  
2. We checked the builder attestations  
3. We performed checks on our project and attested the results.  
4. We checked the results of 1-3 before triggering the build  
5. We verified the resulting binaries before releasing them and produced VSAs to capture the verification results.  
6. We published all the signed security metadata in a bundle along with the binaries.
7. Finally, end users can check the binaries using the verification summaries. If they wish, they can also perform the complete verification themselves, as all the data and policies are open

The example project repository is open source, feel free to suggest improvements
or fix any bugs, just not the CVEs ;)

## Resources

This is a list of the tools used in the demo, most of them have GitHub actions
ready to use, check the
[Fritoto release workflow](https://github.com/carabiner-dev/demo-slsa-e2e/blob/main/.github/workflows/release.yaml)
for examples.

Fritoto, the SLSA e2e demo:<br>
[https://github.com/carabiner-dev/demo-slsa-e2e](https://github.com/carabiner-dev/demo-slsa-e2e)

🔴🟡🟢 AMPEL, The Amazing Multipurpose Policy Engine (and L)<br>
[https://github.com/carabiner-dev/ampel](https://github.com/carabiner-dev/ampel)

🥨 bnd, the attestation multitool<br>
https://github.com/carabiner-dev/bnd

sourcetool, SLSA Source's CLI to secure your git history<br>
https://github.com/slsa-framework/source-tool

Tejolote, The kubernetes SLSA Build Attestter<br>
https://github.com/kubernetes-sigs/tejolote

OSV Scanner, Vulnerability scanner leveraging OSV data<br>
https://github.com/google/osv-scanner

Vexctl, OpenVEX’s tool to manage vex documents<br>
[https://github.com/openvex/vexctl](https://github.com/openvex/vexctl)

Beaker, Test run attester<br>
[https://github.com/carabiner-dev/beaker](https://github.com/carabiner-dev/beaker)

Unpack, experimental dependency extractor<br>
https://github.com/carabiner-dev/unpack
