SECTIONS
{
        . = 0x0;
        .text : {
            *(.text .text.* .data .data.* .rodata .rodata.* .bss)
        }
        .unused : {
            *(.note.* .eh_frame* .comment)
        }
}
