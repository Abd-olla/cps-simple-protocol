SECTIONS
{
    .secure_data :
    {
        KEEP(*(.secure_data))
    } > SECURE_RAM
}

