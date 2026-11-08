#!/usr/bin/env python3
from pathlib import Path
import hashlib, struct, sys

# Fail-closed verifier for the audited Y73S GCC _paging_init/start layout.
PROLOGUE = [0xA9017BFD,0x910043FD,0xA90253F3,0x52800034,0xA9035BF5,0xD2800015,0xA90463F7,0xA9056BF9,0xA90673FB]
RESTORE = [0xF94003AA,0xA9415153,0xA9425955,0xA9436157,0xA9446959,0xA945715B,0xF940015D,0xF940055E]
RET=0xD65F03C0
def main(p):
    b=Path(p).read_bytes()
    if len(b)%4: raise ValueError("KPIMG size is not 4-byte aligned")
    w=list(struct.unpack("<"+"I"*(len(b)//4),b))
    ph=[]; th=[]
    for i in range(2,len(w)-len(PROLOGUE)):
        if w[i:i+len(PROLOGUE)]==PROLOGUE:
            sub,add=w[i-2],w[i-1]
            if (sub&0xFFC003FF)==0xD10003FF and (add&0xFFC003FF)==0x910003E0:
                sh=12 if (sub>>22)&1 else 0
                ph.append((((sub>>10)&0xFFF)<<sh))
    for i in range(len(w)-len(RESTORE)-1):
        if w[i:i+len(RESTORE)]==RESTORE and w[i+len(RESTORE)+1]==RET:
            ins=w[i+len(RESTORE)]
            if (ins&0xFFC003FF)==0x9100015F and not ((ins>>22)&1):
                th.append((ins>>10)&0xFFF)
    if len(ph)!=1 or len(th)!=1:
        raise ValueError(f"unknown/ambiguous code layout: prologues={len(ph)} restore_sequences={len(th)}")
    expected=ph[0]-0x10
    print(f"SHA256: {hashlib.sha256(b).hexdigest()}")
    print(f"_paging_init frame=0x{ph[0]:x}; SP restore=0x{th[0]:x}; expected=0x{expected:x}")
    if th[0]!=expected: raise ValueError("SP restore mismatch; refusing artifact")
    print("[PASS] audited stack-frame/register restore layout")
if __name__=="__main__":
    try: main(sys.argv[1])
    except Exception as e: print("[FAIL]",e,file=sys.stderr); sys.exit(2)
