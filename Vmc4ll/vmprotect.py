import pefile
pe = pefile.PE(filePath)
image = pe.get_memory_mapped_image()
baseOffset = 0xB400
handlers = []
for i in range(255):
    offset+=4
    handlers.append(image[offset])
for h in handlers:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(h, 0x1000):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
