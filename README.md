# DevMatrix

A **specification-to-system compiler** that transforms natural language specifications into complete, verifiable full-stack applications.

Same input. Same system. Same hash.

Not as a promise — as a verifiable property.

---

## What is DevMatrix?

Most "AI coding" advances assume software is text. This works for autocomplete. It doesn't work for building systems.

DevMatrix is **not** a copilot, agent, or prompting tool.
It is a **compiler** that produces:

- Complete backend (Python/FastAPI)
- Complete frontend (React/Next.js)
- Generated tests (pytest)
- Infrastructure (Docker, migrations)
- Cryptographic evidence of reproducibility

**Key guarantee**: Same specification → same system → same SHA-256 hash.

---

## Quick Links

| Document | Description |
|----------|-------------|
| [PAPER_EN.md](PAPER_EN.md) | Technical paper (English - canonical) |
| [EVIDENCE_EN.md](EVIDENCE_EN.md) | Reproducibility evidence (English) |
| [HOW_TO_VERIFY.md](HOW_TO_VERIFY.md) | Verification instructions |
| [PAPER.md](PAPER.md) | Technical paper (Spanish) |
| [EVIDENCE.md](EVIDENCE.md) | Reproducibility evidence (Spanish) |

---

## Evidence Summary

Compilations from 3 real-world specifications:

| Spec | Entities | API Routes | Tests | Pass Rate | Grade |
|------|----------|------------|-------|-----------|-------|
| FLOWDESK (Workflow) | 29 | 29 | 513 | 89.8% | A (96.9%) |
| CRM (Ghysels CRM) | 22 | 22 | 328 | 82.7% | B (94.3%) |
| Healthcare (MediCloud) | 17 | 17 | 284 | 95.4% | A (98.6%) |
| **TOTAL** | **68** | **68** | **1,125** | **88.4%** | **A** |

Full details: [EVIDENCE_EN.md](EVIDENCE_EN.md)

---

## Verify It Yourself

```bash
# Quick verification
python verify_fingerprint.py \
  --fingerprint build_fingerprint.json \
  --compare other_build_fingerprint.json
```

If DevMatrix is non-deterministic, one of these must occur:
- Same spec → different `spec_hash`
- Same `spec_hash` → different `code_bundle_hash`

**Current status**: 0 hash variations observed.

See [HOW_TO_VERIFY.md](HOW_TO_VERIFY.md) for detailed instructions.

---

## What Makes This Different

| Aspect | Copilots | Agents | DevMatrix |
|--------|----------|--------|-----------|
| Output | Lines of code | Varies | Complete systems |
| Determinism | No | No | **Yes** |
| Verifiable | No | No | **Yes** |
| Tests | No | Sometimes | **Generated + executed** |
| Reproducible | No | No | **Same hash** |

---

## Files in This Package

```
DOCS/PRESENTATION/
├── README.md              # This file
├── PAPER_EN.md            # Technical paper (English)
├── PAPER.md               # Technical paper (Spanish)
├── EVIDENCE_EN.md         # Evidence (English)
├── EVIDENCE.md            # Evidence (Spanish)
├── HOW_TO_VERIFY.md       # Verification guide
├── verify_fingerprint.py  # Verification script
├── LICENSE                # CC-BY 4.0 (docs) + MIT (script)
├── CITATION.cff           # Citation metadata
└── examples/
    └── build_fingerprint_example.json
```

---

## Citation

If you reference this work:

```bibtex
@misc{ghysels2026devmatrix,
  author = {Ghysels, Ariel Eduardo},
  title = {DevMatrix: A Specification-to-System Compiler},
  year = {2026},
  url = {https://github.com/arielghysels/devmatrix-paper}
}
```

See [CITATION.cff](CITATION.cff) for full citation metadata.

---

## License

- **Documentation**: CC-BY 4.0
- **Verification script**: MIT
- **DevMatrix software**: Proprietary (not included)

---

## Contact

**Ariel Eduardo Ghysels**
- Supervised verification sessions available
- Access to compilations under NDA

---

*This is not a demo. This is evidence.*
