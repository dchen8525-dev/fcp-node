// FECSTAT v1: frozen 128-byte oob report. Port of src/fcp/fecstat.{h,cc}.
// Every integer field is little-endian. Offsets are asserted in fecstat.h and
// mirrored here; changing any of them breaks wire compatibility.

import {
  FECSTAT_LEN, FECSTAT_VERSION, FECSTAT_MAGIC, FECSTAT_MAX_FORWARD_SETS,
  FLG_LEDGER, FLG_DIRECTION, FLG_TAIL_DROPPED, FLG_LATE_RECOVERY,
} from '../constants.ts';
import { getLe16, getLe32, putLe16, putLe32, bytesEqual, seqAfter } from '../wire.ts';

export interface FecstatPacket {
  salt: Uint8Array;
  ver: number;
  flg: number;
  intervalMs: number;
  accountedThroughSetId: number;
  setsExpected: number;
  dataExpected: number;
  dataRxOrig: number;
  dataRecoveredDl: number;
  dataRecoveredLate: number;
  dataDelivered: number;
  parityRx: number;
  parityExpected: number;
  setsKUnknown: number;
  setsFull: number;
  authFail: number;
  lateDup: number;
  structFail: number;
  repairLatP50Ms: number;
  repairLatP95Ms: number;
  dataBytesRx: number;
  parityBytesRx: number;
  setsTailDropped: number;
  dataLateRx: number;
  setsPartial: number;
  ledgerGroups: number;
  ledgerFailPpm: number;
  ledgerMeta: number;
}

export const FecstatStatus = {
  Ok: 0, BadLength: 1, BadMagic: 2, BadVer: 3, BadSalt: 4, Duplicate: 5, Stale: 6,
} as const;
export type FecstatStatusValue = (typeof FecstatStatus)[keyof typeof FecstatStatus];

export function makeFecstatPacket(salt: Uint8Array): FecstatPacket {
  return {
    salt: Buffer.from(salt), ver: FECSTAT_VERSION, flg: 0, intervalMs: 0,
    accountedThroughSetId: 0, setsExpected: 0, dataExpected: 0, dataRxOrig: 0,
    dataRecoveredDl: 0, dataRecoveredLate: 0, dataDelivered: 0, parityRx: 0,
    parityExpected: 0, setsKUnknown: 0, setsFull: 0, authFail: 0, lateDup: 0,
    structFail: 0, repairLatP50Ms: 0, repairLatP95Ms: 0, dataBytesRx: 0,
    parityBytesRx: 0, setsTailDropped: 0, dataLateRx: 0, setsPartial: 0,
    ledgerGroups: 0, ledgerFailPpm: 0, ledgerMeta: 0,
  };
}

export function encodeFecstat(p: FecstatPacket): Buffer {
  const out = Buffer.alloc(FECSTAT_LEN);
  FECSTAT_MAGIC.copy(out, 0);
  Buffer.from(p.salt).copy(out, 16);
  out[24] = p.ver;
  out[25] = p.flg;
  putLe16(p.intervalMs, out, 26);
  const u32: Array<[number, number]> = [
    [28, p.accountedThroughSetId], [32, p.setsExpected], [36, p.dataExpected],
    [40, p.dataRxOrig], [44, p.dataRecoveredDl], [48, p.dataRecoveredLate],
    [52, p.dataDelivered], [56, p.parityRx], [60, p.parityExpected],
    [64, p.setsKUnknown], [68, p.setsFull], [72, p.authFail], [76, p.lateDup],
    [80, p.structFail], [88, p.dataBytesRx], [92, p.parityBytesRx],
    [96, p.setsTailDropped], [100, p.dataLateRx], [104, p.setsPartial],
    [108, p.ledgerGroups], [112, p.ledgerFailPpm], [116, p.ledgerMeta],
  ];
  for (const [off, v] of u32) putLe32(v, out, off);
  putLe16(p.repairLatP50Ms, out, 84);
  putLe16(p.repairLatP95Ms, out, 86);
  return out; // reserved[2] at 120..127 stays zero
}

export function decodeFecstat(input: Uint8Array, salt: Uint8Array): { status: FecstatStatusValue; packet: FecstatPacket | null } {
  if (input.length < 25) return { status: FecstatStatus.BadLength, packet: null };
  if (!bytesEqual(FECSTAT_MAGIC, input, 16)) return { status: FecstatStatus.BadMagic, packet: null };
  if (input[24] !== FECSTAT_VERSION) return { status: FecstatStatus.BadVer, packet: null };
  if (input.length !== FECSTAT_LEN) return { status: FecstatStatus.BadLength, packet: null };
  if (!bytesEqual(salt, input.subarray(16, 24), 8)) return { status: FecstatStatus.BadSalt, packet: null };
  const p = makeFecstatPacket(input.subarray(16, 24));
  p.ver = input[24];
  p.flg = input[25];
  p.intervalMs = getLe16(input, 26);
  p.accountedThroughSetId = getLe32(input, 28);
  p.setsExpected = getLe32(input, 32);
  p.dataExpected = getLe32(input, 36);
  p.dataRxOrig = getLe32(input, 40);
  p.dataRecoveredDl = getLe32(input, 44);
  p.dataRecoveredLate = getLe32(input, 48);
  p.dataDelivered = getLe32(input, 52);
  p.parityRx = getLe32(input, 56);
  p.parityExpected = getLe32(input, 60);
  p.setsKUnknown = getLe32(input, 64);
  p.setsFull = getLe32(input, 68);
  p.authFail = getLe32(input, 72);
  p.lateDup = getLe32(input, 76);
  p.structFail = getLe32(input, 80);
  p.repairLatP50Ms = getLe16(input, 84);
  p.repairLatP95Ms = getLe16(input, 86);
  p.dataBytesRx = getLe32(input, 88);
  p.parityBytesRx = getLe32(input, 92);
  p.setsTailDropped = getLe32(input, 96);
  p.dataLateRx = getLe32(input, 100);
  p.setsPartial = getLe32(input, 104);
  p.ledgerGroups = getLe32(input, 108);
  p.ledgerFailPpm = getLe32(input, 112);
  p.ledgerMeta = getLe32(input, 116);
  return { status: FecstatStatus.Ok, packet: p };
}

/** Half-window monotonic validator (fecstat.cc FecstatValidator::validate). */
export class FecstatValidator {
  private haveLast = false;
  private lastSetId = 0;
  futureRejects = 0;

  validate(input: Uint8Array, salt: Uint8Array): { status: FecstatStatusValue; packet: FecstatPacket | null } {
    const r = decodeFecstat(input, salt);
    if (r.status !== FecstatStatus.Ok || r.packet === null) return r;
    const id = r.packet.accountedThroughSetId;
    if (this.haveLast) {
      if (id === this.lastSetId) return { status: FecstatStatus.Duplicate, packet: r.packet };
      if (!seqAfter(id, this.lastSetId)) return { status: FecstatStatus.Stale, packet: r.packet };
      const forward = (id - this.lastSetId) >>> 0;
      if (forward > FECSTAT_MAX_FORWARD_SETS) {
        ++this.futureRejects;
        return { status: FecstatStatus.Stale, packet: r.packet };
      }
    }
    this.haveLast = true;
    this.lastSetId = id;
    return r;
  }
}

export function ledgerK(p: FecstatPacket): number { return p.ledgerMeta & 0xff; }
export function ledgerBurstKl(p: FecstatPacket): number { return p.ledgerMeta >>> 16; }
export { FLG_LEDGER, FLG_DIRECTION, FLG_TAIL_DROPPED, FLG_LATE_RECOVERY };
