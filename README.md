# chimera_pe

[![Build status](https://ci.appveyor.com/api/projects/status/hmmyqliswhl10c4u?svg=true)](https://ci.appveyor.com/project/hasherezade/chimera-loader)

ChimeraPE (a PE injector type - alternative to: RunPE, ReflectiveLoader, etc) - a ready-made template for manual loading of PEs, loading imports payload-side.<br/><hr/>
This project contais two PoCs that can be used as templates:<br/>
+ chimera_pe - is a loader with two sample payloads: demo32.bin and demo64.bin, that are injected into calc.exe (appropriately: 64 or 32 bit)
+ chimera_pe_payload_template - is a template basing on which you can build your own payload to be injected
