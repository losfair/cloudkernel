SECTIONS
{
        . = 0x60000000;
        .text : { *(.text .text.*) }
        .data : { *(.data .data.* .rodata .rodata.*) }
}
