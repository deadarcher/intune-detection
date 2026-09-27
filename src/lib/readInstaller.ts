/**
 * Read an installer from the user's disk and parse it. Shared, because the rule about WHEN to read
 * the whole file is not obvious and getting it wrong fails silently.
 *
 * Big files get only the head: every engine marker (PE section table, stub strings, archive magic)
 * sits at the front, and full reads plus full-buffer signature scans are what used to freeze the
 * tab on 300+ MB Burn bundles.
 *
 * EXCEPT MSI. That reasoning holds for stub-fronted engines (Inno, NSIS, Burn) and is FALSE for an
 * OLE compound file: an MSI's directory and its Property / SecureCustomProperties streams can sit
 * anywhere, including past the slice. Parsing a truncated MSI makes analyzeMsi throw, detectInstaller
 * swallows it, and you get engine detection with ZERO properties - silently losing the most valuable
 * output on exactly the enterprise packages that need it. Measured on a 111 MB MSI whose
 * SecureCustomProperties holds APIKEY;APIURL;DEREGISTER: none surfaced. So sniff the CFB magic and
 * read MSIs whole.
 *
 * This lives in one place because a second copy of it would look correct and quietly lose MSI
 * properties, which is the failure this codebase has already paid for once.
 */
import { detectInstaller } from './installerDetect';
import type { DetectionResult } from './installerDetect';

/** Engine stubs and markers all live in the first few MB. */
export const DETECT_SLICE = 32 * 1024 * 1024;

/** OLE compound file magic - an MSI, and the one format that must be read whole. */
export function isCompoundFile(head: Uint8Array): boolean {
  return head.length >= 8 &&
    head[0] === 0xd0 && head[1] === 0xcf && head[2] === 0x11 && head[3] === 0xe0 &&
    head[4] === 0xa1 && head[5] === 0xb1 && head[6] === 0x1a && head[7] === 0xe1;
}

export interface ReadResult {
  buf: ArrayBuffer;
  result: DetectionResult;
  /** True when only the head was read, so callers know `buf` is not the whole file. */
  partial: boolean;
}

/**
 * @param onStatus called when a slow whole-file read is about to happen, so the caller can say so
 *                 rather than looking frozen.
 */
export async function readForDetection(
  file: File,
  onStatus?: (msg: string) => void,
): Promise<ReadResult> {
  const probe = new Uint8Array(await file.slice(0, 8).arrayBuffer());
  const cfb = isCompoundFile(probe);
  const partial = file.size > DETECT_SLICE && !cfb;
  if (cfb && file.size > DETECT_SLICE) {
    onStatus?.(`Reading all ${Math.round(file.size / 1024 / 1024)} MB - an MSI's property tables can live past the head of the file…`);
  }
  const buf = partial ? await file.slice(0, DETECT_SLICE).arrayBuffer() : await file.arrayBuffer();
  return { buf, result: detectInstaller(buf, file.name, partial ? file.size : undefined), partial };
}
