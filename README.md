# Intune detection rule

**Drop an installer and get the Intune Win32 detection rule for it, with the version operator set so a new build still applies.** MSI, EXE or install script. Nothing is uploaded: the file is parsed entirely in your browser.

**Use it now (hosted):** https://getrff.com/intune-detection/

---

## Why detection is the step that breaks

You can test an install command in about a minute. Run it, and it either goes in silently or it doesn't. Detection has no moment like that. A bad rule works on your test box and falls over months later across the fleet, and what you see (an app reinstalling itself over and over, or one that says it's installed when it isn't) doesn't look like a detection problem.

The usual culprits:

- **"Equals" as the version operator.** It matches one build. Ship an update, Intune decides the app is gone, and it pushes the old version back over the new one. Every rule here uses **Greater than or equal to**, which survives updates and still comes back not-detected when the app really is missing or older.
- **A bare file-exists rule.** It only proves something was written to disk once. It reports detected after a half-finished install and after a failed upgrade. This tool never emits one without a version check.
- **A script rule that exits 0 on both branches.** Then it can never report not-detected. The script generated here writes to STDOUT and exits 0 on the installed branch only.
- **Pushing the same version again.** A repair, a changed payload or a re-enrolment: every rule that describes the software is already true, so Intune reports detected and never runs the install. Tick the box and you get a deployment-token rule instead, which you bump to make every machine take it again.

## What you get

The rules come ranked, best first, each marked with how much of it came from the file:

- **From the package.** Read straight out of the installer. For an MSI that's the product code and version from its Property table.
- **Very likely.** The uninstall-key registry rule, when the engine tells us where it writes but not every value. When the registry view isn't certain (a 32-bit installer on 64-bit Windows lands under WOW6432Node) you get both paths.
- **Template.** The file doesn't say, so the fields it can't fill are listed in red. Install it on one machine, read the real values there, and finish the rule.

It won't invent an install path it can't know, and it won't fill in a plausible-looking company name you'd ship untouched. For a script deployment that installs nothing detectable (printers, a registry change) it gives you a marker-key rule plus the lines that write the marker, placed so a failed install can't report success.

## Run it yourself

It's a static site. Nothing runs server-side, so any web server will do.

```
npm install
npm run dev        # http://localhost:4321
npm run build      # static files in dist/
```

Or with Docker:

```
docker run --rm -p 8080:80 ghcr.io/deadarcher/intune-detection:latest
```

or `docker compose up -d` from this folder. Then open http://localhost:8080.

## Use the engine directly

The engine is plain TypeScript with no dependencies: [`src/lib/intuneDetection.ts`](src/lib/intuneDetection.ts) builds the rules from what the installer parser ([`src/lib/installerDetect.ts`](src/lib/installerDetect.ts) and [`src/lib/msi.ts`](src/lib/msi.ts)) reads out of the file. To run it over a folder of installers from Node:

```ts
// detect.ts - run with: npx tsx detect.ts setup.msi
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { detectInstaller } from './src/lib/installerDetect';
import { buildDetectionAdvice } from './src/lib/intuneDetection';

const path = process.argv[2];
const b = readFileSync(path);
const parsed = detectInstaller(b.buffer.slice(b.byteOffset, b.byteOffset + b.length), basename(path));
const advice = buildDetectionAdvice(parsed);

for (const rule of advice.rules) {
  console.log(`${rule.rank}. [${rule.confidence}] ${rule.title}`);
  for (const f of rule.fields) console.log(`   ${f.label}: ${f.value}`);
}
```

In the browser, use `readForDetection` from [`src/lib/readInstaller.ts`](src/lib/readInstaller.ts) instead of reading the file yourself. It reads large EXEs by their head only (every engine marker sits there) but always reads an MSI whole, because an MSI's property tables can sit anywhere in the file and a truncated read silently loses them.

## Privacy

Your installer is read and parsed in the browser. There's no upload, no storage and no account, and this build loads nothing from a third party: no analytics, no font CDN. Open your browser's developer tools and watch the network tab if you want to check.

## Issues

If it gives you a wrong rule, open an issue with the installer's name, where to download it, and the rule you expected. The installer parser is shared with [SwitchHunt](https://github.com/deadarcher/SwitchHunt), so an engine the parser misreads is usually worth reporting there too.

The engine files are kept byte-identical with the hosted copy at getrff.com, so fixes land in both.

## License

MIT. See [LICENSE](LICENSE).

---

Built by the [RFF](https://getrff.com) team. RFF is a Windows RMM: deploy, patch and remote-control your fleet from a browser tab, free for your first 100 endpoints.
