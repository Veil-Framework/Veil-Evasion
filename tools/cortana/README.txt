This Cortana script integrates Veil-Evasion (https://github.com/Veil-Framework/Veil-Evasion)
into Armitage/Cobalt Strike under 'Attacks' -> 'Veil-Evasion'

It is part of a Cortana script from https://github.com/HarmJ0y/cortana.
For a more complete Cortana repo, visit https://github.com/rsmudge/cortana-scripts


On loading, the installation path for Veil-Evasion will be prompted for.

Payloads can (optionally) be set to be substituted into PSEXEC calls on the fly.

Existing Cobalt Strike listeners can be selected and appropriate options will
be filled in.

On generation, payload options are saved, even across restarts of Armitage/Cobalt Strike.


Double-clicking 'Payload' will dynamically load the payloads available in
the associated Veil-Evasion install.

Double-clicking 'MSFPayload' will bring up a list of compatible
metasploit shellcode specifications.

Double-clicking LHOST will reset the LHOST variable to the local IP.


-- harmj0y
