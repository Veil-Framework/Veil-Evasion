
; Macroinstructions for interfacing the COM (Component Object Model) classes

macro cominvk object,proc,[arg]
 { common
    if ~ defined com.object.#object
     display 'Error: not a COM object.',0Dh,0Ah
     rb -1
    end if
    macro call dummy
    \{ mov rax,[object]
       mov rax,[rax]
       call [rax+object#.#proc] \}
    fastcall proc,[object],arg
    purge call }

macro comcall handle,interface,proc,[arg]
 { common
    if ~ defined com.interface.#interface
     display 'Error: not a COM interface.',0Dh,0Ah
     rb -1
    end if
    macro call dummy
    \{ if handle eqtype rax | handle eqtype 0
	push handle
	local ..handle
	label ..handle at handle
	mov rax,[..handle]
       else
	mov rax,handle
	mov rax,[rax]
       end if
       call [rax+interface#.#proc] \}
    fastcall proc,handle,arg
    purge call }

macro interface name,[proc]
 { common
    struc name \{
    match any, fields@struct \\{ fields@struct equ fields@struct,.,name, \\}
    match , fields@struct \\{ . dq ?
    virtual at 0
   forward
    .#proc dq ?
   common
    com.object.\#. = com.interface.#name
    end virtual \\} \}
    virtual at 0
   forward
     name#.#proc dq ?
   common
     com.interface.#name = $ shr 2
    end virtual }

