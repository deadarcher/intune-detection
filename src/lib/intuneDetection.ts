import type { DetectionResult, InstallerEngine } from './installerDetect';

/**
 * Intune Win32 detection-rule generator.
 *
 * WHY THIS EXISTS. Detection is the step that silently breaks Win32 app deployment, and the
 * failure is always the same shape: a rule that was true when you wrote it and stops being true
 * later. The threads are six years deep and identical - "I suck at detection methods"; "if the
 * rule checks a file exists and I republish a new version, it never applies, right?"; a script
 * that exits 0 in both the installed and not-installed branches so it can never report failure;
 * a bare file-exists rule that reports not-detected on machines where the install plainly worked.
 *
 * The information needed to write the rule correctly is already inside the installer, and
 * SwitchHunt already parses it. This turns that parse into the rule.
 *
 * WHAT IT REFUSES TO DO. It will not invent an install path it cannot know, and it will not emit
 * a file-exists rule without a version comparison. Both produce a rule that looks right in the
 * portal and rots on the first update, which is the exact complaint that makes people search for
 * this in the first place.
 */

export type RuleKind = 'msi' | 'registry' | 'file' | 'script' | 'tag' | 'reinstall';
export type Confidence = 'exact' | 'likely' | 'template';

export interface DetectionRule {
  kind: RuleKind;
  /** How much of this came from the binary vs. how much the admin still has to supply. */
  confidence: Confidence;
  /** One-line heading for the card. */
  title: string;
  /** Field-by-field, matching the labels Intune actually shows, so it can be copied across. */
  fields: { label: string; value: string; note?: string }[];
  /** Why this rule and not another. */
  rationale: string;
  /** What the admin MUST still fill in. Empty when the rule is complete as generated. */
  todo?: string[];
  /** For script rules only. */
  script?: string;
  /** 1-based position in the ordered set. Assigned after assembly, not by the rule builders. */
  rank?: number;
  /** When to reach for THIS one rather than the one above it. */
  pick?: string;
}

export interface DetectionAdvice {
  rules: DetectionRule[];
  /** Traps that apply regardless of which rule was chosen. */
  warnings: string[];
  /** One line above the cards saying what this set IS. Differs for a script deployment. */
  lead?: string;
  /**
   * Set when NOTHING in the package identifies what it installs, so every rule offered is a
   * template the file cannot finish. Without this the page reads as three usable answers.
   */
  notice?: string;
}

/**
 * The version operator is the whole ballgame.
 *
 * "Equals" is the default people reach for and it is wrong in a specific, delayed way: the app
 * installs, detection matches, and then the next version ships and the rule no longer matches
 * anything, so Intune reports it as not-installed forever and reinstalls the OLD build over the
 * new one. "Greater than or equal to" survives the update and still fails honestly when the app
 * is genuinely absent or older.
 */
const VERSION_OP = 'Greater than or equal to';

/** Uninstall keys live in two views; a 32-bit installer on x64 lands under WOW6432Node. */
const UNINSTALL_64 = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall';

function msiRule(productCode: string, version?: string): DetectionRule {
  const fields = [
    { label: 'Rule type', value: 'MSI' },
    { label: 'MSI product code', value: productCode, note: 'Read from the package Property table.' },
  ];
  if (version) {
    fields.push(
      { label: 'MSI product version check', value: 'Yes' },
      { label: 'Operator', value: VERSION_OP, note: 'NOT "Equals" - see the note below.' },
      { label: 'Value', value: version },
    );
  }
  return {
    kind: 'msi',
    confidence: 'exact',
    title: 'MSI product code' + (version ? ' + version' : ''),
    fields,
    rationale:
      'This is the same GUID Windows Installer uses to identify the product, so it can’t drift. It’s ' +
      'read straight out of the package.',
    todo: version
      ? undefined
      : ['The package doesn’t declare a ProductVersion, so this rule matches any installed version. Add a version check by hand if you ship updates.'],
  };
}

function registryRule(
  engine: InstallerEngine, product?: string, version?: string, productCode?: string,
): DetectionRule {
  // Windows Installer names the ARP subkey after the ProductCode, so for an MSI this path is the
  // same GUID the rule above already shows - there is nothing to go and look up. Only the engines
  // that choose their own subkey name at build time need a machine to read it off.
  const known = engine === 'msi' && !!productCode;
  const keyPath = known
    ? `${UNINSTALL_64}\\${productCode}`
    : product
      ? `${UNINSTALL_64}\\<key for ${product}>`
      : `${UNINSTALL_64}\\<uninstall key>`;
  return {
    kind: 'registry',
    confidence: known ? 'likely' : 'template',
    title: 'Uninstall-key registry rule',
    fields: [
      { label: 'Rule type', value: 'Registry' },
      {
        label: 'Key path',
        value: keyPath,
        note: known
          ? 'The uninstall subkey is the product code, so this came out of the package.'
          : 'Find the exact subkey on a machine that has the app installed.',
      },
      { label: 'Value name', value: 'DisplayVersion' },
      { label: 'Detection method', value: 'String comparison' },
      { label: 'Operator', value: VERSION_OP },
      { label: 'Value', value: version ?? '<installed version>' },
      {
        label: 'Associated with a 32-bit app on 64-bit clients',
        value: engine === 'msi' ? 'No' : 'Check the machine',
        note: 'If the key only exists under WOW6432Node, set this to Yes or the rule reads an empty view.',
      },
    ],
    rationale: known
      ? 'Windows Installer names the uninstall key after the product code, so this path comes straight out ' +
        'of the package. The one thing left to sort out is the registry view. A 32-bit package lands under ' +
        'WOW6432Node, and the flag below is how you tell Intune which one to read.'
      : 'This engine writes an Add/Remove Programs entry, but it picks the subkey name at build time and you ' +
        'can’t get it out of the installer. DisplayVersion is the value to compare against, and that part is standard.',
    todo: known
      ? ['Confirm which registry view the key lands in before setting the 32-bit flag.']
      : [
          'Install the app on one machine, then find its subkey under the Uninstall path and paste the full path above.',
          'Confirm which registry view the key lands in before setting the 32-bit flag.',
        ],
  };
}

function fileRule(product?: string, version?: string): DetectionRule {
  return {
    kind: 'file',
    confidence: 'template',
    title: 'File version rule',
    fields: [
      { label: 'Rule type', value: 'File' },
      { label: 'Path', value: `C:\\Program Files\\${product ?? '<vendor>\\<app>'}` },
      { label: 'File or folder', value: '<main executable>.exe' },
      { label: 'Detection method', value: 'String comparison (version)' },
      { label: 'Operator', value: VERSION_OP },
      { label: 'Value', value: version ?? '<file version>' },
    ],
    rationale:
      'Last resort, for when the package doesn’t give you anything stable to key on. Compare the file ' +
      'version, not whether the file is there. A file-exists rule stays true forever once the app is ' +
      'installed, so you can never update it through Intune again.',
    todo: [
      'Install it once and confirm the real path. Vendors move between Program Files and Program Files (x86).',
      'Use the main binary’s file version. It’s often not the same as the marketing version.',
    ],
  };
}

/**
 * Script rules are offered LAST and with a working template, because the two things that break
 * them are invisible in the portal: the two-part contract (exit 0 AND stdout), and the fact that
 * detection runs as SYSTEM, so HKCU is SYSTEM's own hive and a per-user install is unfindable there.
 */
/**
 * SCRIPT DEPLOYMENTS - the case where there is nothing in the file to detect.
 *
 * A PowerShell deployment (printers, a registry change, a config drop) installs something that
 * never registers a product code, an uninstall key or a versioned binary. Every field-based rule
 * above would be guessing at software this file does not install, so none of them are offered.
 *
 * The standard answer is to stop looking for something to detect and leave one instead: the install
 * script writes a marker key it owns, and the rule reads that back. Same shape as detecting a
 * printer on the key Windows itself creates, except here you are the one who wrote it.
 *
 * The trap is ORDER. A tag written at the top of the script, or written unconditionally at the
 * bottom, reports a failed install as a success forever, which is worse than having no rule.
 */
function tagRule(name: string, version?: string, org?: string): DetectionRule {
  const ver = version ?? '1.0.0';
  const seg = orgSegment(org);
  const named = seg !== ORG_PLACEHOLDER;
  const key = `HKLM:\\SOFTWARE\\${seg}\\${name}`;
  const script = `# Put this at the END of your install script, on the success path only. A tag written before
# the work is done, or written no matter how it went, makes a failed install look installed
# forever. That is worse than having no detection rule at all.
$tag = '${key}'
New-Item -Path $tag -Force | Out-Null
New-ItemProperty -Path $tag -Name 'Version' -Value '${ver}' -PropertyType String -Force | Out-Null

# In your UNINSTALL script, take it back off, or Intune keeps reporting the app as installed:
# Remove-Item -Path $tag -Recurse -Force -ErrorAction SilentlyContinue`;
  return {
    kind: 'tag',
    confidence: 'template',
    title: 'Write your own tag, then detect on it',
    fields: [
      { label: 'Rule type', value: 'Registry' },
      {
        label: 'Key path',
        value: `HKEY_LOCAL_MACHINE\\SOFTWARE\\${seg}\\${name}`,
        note: named
          ? `Two segments: ${seg} is the root you own, and ${name} is this one script. Keep the same root for everything you deploy this way and they all sit together under one key.`
          : 'Two segments: a root you own, then one subkey per script. Put your name in the box above and this fills itself in, here and in the script below.',
      },
      { label: 'Value name', value: 'Version' },
      { label: 'Detection method', value: 'String comparison' },
      { label: 'Operator', value: VERSION_OP, note: 'So the next version of the script still detects.' },
      { label: 'Value', value: ver },
      {
        label: 'Associated with a 32-bit app on 64-bit clients',
        value: 'No',
        note: 'Assumes the app installs in 64-bit context. If it runs 32-bit the write lands in WOW6432Node and this has to be Yes to match.',
      },
    ],
    rationale:
      'There is nothing in this file to detect on, because a script deployment leaves no package ' +
      'behind. So you leave the marker yourself. The install script writes a key it owns, and the ' +
      'rule reads that key back.',
    todo: [
      ...(named ? [] : [`Replace ${ORG_PLACEHOLDER} with your own short name, in BOTH the key path and the script.`]),
      'Write the tag ONLY after the install has actually succeeded, not at the top of the script.',
      'Remove the tag in your uninstall script, or the app reports installed forever.',
      'Bump the Version value whenever you change the script, so the new one deploys.',
    ],
    script,
  };
}

function scriptRule(product?: string, version?: string): DetectionRule {
  const ver = version ?? '0.0.0.0';
  const script = `# Intune wants BOTH: exit code 0 AND something on STDOUT. Either one on its own isn't detected.
# Watch the failure path. One stray Write-Output down there and every machine reports detected
# forever.
#
# This runs as SYSTEM, so HKCU is SYSTEM's own hive and a per-user install isn't in it. Walk the
# loaded hives under HKEY_USERS if that's what you're after.
$paths = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
$app = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
       Where-Object { $_.DisplayName -like '*${(product ?? '<app name>').replace(/'/g, "''")}*' } |
       Select-Object -First 1

if (-not $app) { exit 1 }

# Cast to [version] when it'll take one. Plenty of vendors ship things like "2024 R2" that won't.
try {
  if ([version]$app.DisplayVersion -ge [version]'${ver}') { Write-Output 'detected'; exit 0 }
} catch {
  if ($app.DisplayVersion -ge '${ver}') { Write-Output 'detected'; exit 0 }
}
exit 1`;
  return {
    kind: 'script',
    confidence: 'template',
    title: 'PowerShell detection script',
    fields: [
      { label: 'Rule type', value: 'Use a custom detection script' },
      { label: 'Run script as 32-bit process on 64-bit clients', value: 'No' },
      { label: 'Enforce script signature check', value: 'No' },
    ],
    rationale:
      'Use this when there’s no stable product code and the uninstall key name changes between versions. ' +
      'It matches on DisplayName across both registry views and compares DisplayVersion.',
    todo: ['Check the DisplayName wildcard matches exactly one product on a real machine.'],
    script,
  };
}

/** Traps that apply to every rule, drawn from what actually breaks in the field. */
function universalWarnings(engine: InstallerEngine): string[] {
  const w = [
    'Never use a bare "file or folder exists" rule. It stays true after the first install, so Intune stops ' +
      're-evaluating and you can never update the app again. This is the most common detection mistake there is.',
    'Detection runs as SYSTEM. HKCU is SYSTEM’s own hive and %APPDATA% is SYSTEM’s profile, so neither one ' +
      'can see a per-user install.',
    'The Intune Management Extension is 32-bit. If the "32-bit app on 64-bit clients" flag isn’t set right, ' +
      'HKLM\\SOFTWARE reads WOW6432Node and System32 reads SysWOW64, so you’re looking in the wrong place ' +
      'and the app won’t be there.',
  ];
  if (engine === 'msi') {
    w.push(
      'An MSI major upgrade changes the product code. If this app self-updates, a product-code rule comes back ' +
        'not-installed after the update and Intune pushes the old build over the new one. Detect on version for anything that updates itself.',
    );
  }
  if (engine === 'not-installer') {
    w.push(
      'A tag your script writes is only as honest as the script. Write it on the success path only ' +
        'and remove it on uninstall, or Intune reports installed on machines where the work failed or was undone.',
    );
  }
  if (engine === 'msix') {
    w.push('MSIX/AppX isn’t a Win32 app. Deploy it as a Line-of-business app or via the Company Portal, not as Win32 with a detection rule.');
  }
  return w;
}

/**
 * Build the ordered rule set for a parsed installer. Best rule first; the alternatives stay
 * visible because the best one is not always available on a given machine.
 */
/**
 * The organisation segment of a tag key. Left as a VISIBLE placeholder until the user supplies one:
 * a plausible-looking default (Contoso, Acme) is the kind of thing that ships to production
 * untouched, and this tool's whole premise is that it does not invent values it cannot know.
 */
const ORG_PLACEHOLDER = '<YourCompany>';

/** Registry key names tolerate spaces; stripping them keeps the pasted path unambiguous. */
function orgSegment(org?: string): string {
  const clean = (org ?? '').trim().replace(/[^A-Za-z0-9.-]+/g, '');
  return clean || ORG_PLACEHOLDER;
}

export interface AdviceOptions {
  /** Organisation name for the tag key, typed by the user. Blank keeps the placeholder. */
  org?: string;
  /**
   * "I need to push this again at the SAME version." Changes the answer completely: every rule
   * derived from the package is already true before the deployment starts, so Intune reports
   * detected and never runs it. See reinstallRule.
   */
  reinstall?: boolean;
  /** The token stamped per redeploy. Blank renders a visible placeholder. */
  deploymentId?: string;
}

/**
 * REDEPLOYING THE SAME VERSION - the case where every other rule on this page is guaranteed wrong.
 *
 * A repair, a corrupted install, a payload that changed while the version did not, a re-enrollment.
 * The product code is already installed. DisplayVersion already matches. The file is already on
 * disk at the right version. So Intune evaluates detection BEFORE installing, finds the app, reports
 * detected, and never runs your deployment. Nothing fails. Nothing happens either, which is worse,
 * because the machine looks compliant.
 *
 * The fix is to stop detecting the SOFTWARE and start detecting THIS DEPLOYMENT. The install script
 * stamps a token you control, and the rule looks for that token. Bump the token and every machine
 * falls out of compliance and takes the install again - deliberately, on your schedule, with the
 * vendor version never entering into it.
 *
 * THE FAILURE MODE IS A MISMATCH. The token lives in exactly two places, the script and the rule,
 * and they have to agree. Bump it in the rule but not the script and every machine installs forever
 * in a loop, because detection can never be satisfied. Bump it in the script but not the rule and
 * nothing redeploys at all. That is the whole risk of this pattern and it is worth saying out loud.
 */
function reinstallRule(name: string, org?: string, token?: string): DetectionRule {
  const seg = orgSegment(org);
  const named = seg !== ORG_PLACEHOLDER;
  const tok = (token ?? '').trim() || '<bump-me>';
  const key = `HKLM:\\SOFTWARE\\${seg}\\${name}`;
  const script = `# Run at the END of your install script, on the success path only.
#
# DeploymentId is the whole trick: it is YOUR value, not the vendor's version. Change it and every
# machine reports not-detected and takes the install again. Leave it alone and nothing moves.
#
# It must match the Value in the detection rule EXACTLY. If the two ever disagree, the app either
# reinstalls forever or never reinstalls at all.
$tag = '${key}'
New-Item -Path $tag -Force | Out-Null
New-ItemProperty -Path $tag -Name 'DeploymentId' -Value '${tok}' -PropertyType String -Force | Out-Null`;
  return {
    kind: 'reinstall',
    confidence: 'template',
    title: 'Redeploy the same version: detect the deployment, not the software',
    fields: [
      { label: 'Rule type', value: 'Registry' },
      {
        label: 'Key path',
        value: `HKEY_LOCAL_MACHINE\\SOFTWARE\\${seg}\\${name}`,
        note: named ? '' : 'Put your name in the box above and this fills itself in, here and in the script.',
      },
      { label: 'Value name', value: 'DeploymentId' },
      { label: 'Detection method', value: 'String comparison' },
      {
        label: 'Operator',
        value: VERSION_OP,
        note: 'Greater than or equal to, so machines still carrying the PREVIOUS token fall out of compliance and take the install, while the ones that just ran it stay put.',
      },
      {
        label: 'Value',
        value: tok,
        note: 'Your token, and the only thing you change to trigger a redeploy. A date or a round number sorts correctly as a string: 2026-09-11-r1, then 2026-09-11-r2.',
      },
      {
        label: 'Associated with a 32-bit app on 64-bit clients',
        value: 'No',
        note: 'Assumes the app installs in 64-bit context. If it runs 32-bit the write lands in WOW6432Node and this has to be Yes to match.',
      },
    ],
    rationale:
      'Every rule below this one is already true before the deployment starts - the product code is ' +
      'installed, the version matches, the file is there - so Intune reports detected and never runs ' +
      'the install. Detect the deployment instead: the script stamps a token you own, and bumping ' +
      'that token is what makes machines redeploy.',
    todo: [
      'The token lives in TWO places, the rule and the script. If they ever disagree the app reinstalls forever or never reinstalls at all.',
      'Bump the token once per redeploy, and only when you actually want every machine to run it again.',
      'Write the tag ONLY after the install succeeded, or a failed install reports as a success.',
    ],
    script,
  };
}

/** Files that ARE the deployment rather than a package containing one. */
const SCRIPT_FILE_RE = /\.(ps1|cmd|bat|vbs)$/i;

/** A key name taken from the file, so the example is about THEIR script, not a placeholder. */
function tagNameFor(fileName?: string): string {
  const base = (fileName ?? '').replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9]+/g, '');
  return base || 'YourApp';
}

export function buildDetectionAdvice(d: DetectionResult, opts?: AdviceOptions): DetectionAdvice {
  const rules: DetectionRule[] = [];
  const product = d.msi?.productName ?? d.product;
  const version = d.msi?.productVersion ?? d.version;

  // No installer in the file means no installed product to key on. A file or uninstall-key rule
  // here would be guessing at software this file never installs, so the tag rule is the ONLY one
  // offered - and it is a complete answer rather than a dead end.
  if (d.engine === 'not-installer' || SCRIPT_FILE_RE.test(d.fileName ?? '')) {
    rules.push(tagRule(tagNameFor(d.fileName), version, opts?.org));
    return {
      rules,
      warnings: universalWarnings('not-installer'),
      lead:
        'This is a script, not an installer, so there is nothing inside it to detect. Have the ' +
        'script leave its own marker behind, and detect on that.',
    };
  }

  // Reinstall mode goes FIRST and the rest stay visible underneath, because seeing why they cannot
  // work is the point - they are not alternatives here, they are the trap.
  if (opts?.reinstall) {
    rules.push(reinstallRule(tagNameFor(d.fileName), opts?.org, opts?.deploymentId));
  }

  if (d.msi?.productCode) {
    rules.push(msiRule(d.msi.productCode, d.msi.productVersion));
  }
  // A registry rule is meaningful for anything that writes an ARP entry, which is every desktop
  // installer engine here except MSIX and the self-extractors.
  // 'not-installer' is not tested here any more: it returns early above, with the tag rule. The
  // leftover check was dead code and TypeScript flagged it as a comparison that can never hold.
  if (d.engine !== 'msix' && d.engine !== 'sfx-7z' && d.engine !== 'sfx-winrar') {
    rules.push(registryRule(d.engine, product, version, d.msi?.productCode));
  }
  if (!d.msi?.productCode) {
    rules.push(fileRule(product, version));
  }
  rules.push(scriptRule(product, version));

  // Rank the assembled set. The advice here is about ORDER - which one to try first, and what to
  // fall back to - so it can only be written once the list exists and each rule knows its position.
  // Nobody reading three cards side by side can tell which is preferred from the rules alone.
  const KIND_NAME: Record<RuleKind, string> = {
    msi: 'MSI product code',
    registry: 'registry',
    file: 'file',
    script: 'script',
    tag: 'tag',
    reinstall: 'redeploy',
  };
  // A single rule needs no number and no ordering advice; there is nothing to order it against.
  if (rules.length > 1) rules.forEach((r, i) => {
    r.rank = i + 1;
    r.pick =
      i === 0
        ? 'Try this one first.'
        : i === rules.length - 1
          ? 'Last resort. Use this if nothing above works.'
          : `Fall back to this if the one above doesn’t work, or if you specifically want a ${KIND_NAME[r.kind]} rule.`;
  });

  // A packaged installer that exposes no product code, no stable uninstall key and no known install
  // path leaves every rule incomplete. Ranking them still helps, but presenting three TEMPLATE cards
  // with no other signal reads as three working answers - and the fields they are missing are
  // exactly the ones that cannot be guessed. Say it outright instead.
  const allTemplate = rules.length > 0 && rules.every(r => r.confidence === 'template');

  return {
    rules,
    warnings: universalWarnings(d.engine),
    notice: allTemplate
      ? 'Nothing in this package says what it registers once it is installed, so none of these rules ' +
        'can be finished from the file alone. Install it on one machine, read the real values off ' +
        'that box, then fill them in here. Every red line below is something only that machine can tell you.'
      : undefined,
    lead: opts?.reinstall
      ? `Redeploying the same version, so rule 1 is the only one that can work. The ${rules.length - 1} ` +
        `below it are already true on the machine before the install runs - that is exactly why ` +
        `nothing happens without a token of your own.`
      : rules.length > 1
        ? `${rules.length} rules, in the order you should try them. Start at 1 and only move down ` +
          `if it doesn’t work.`
        : 'One rule for this package.',
  };
}
