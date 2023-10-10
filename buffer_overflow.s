.data
# num1 and num2 represent two separate 32-bit data values that can be combined to form a single 64-bit data value
num1: .word 0xF2345678
num2: .word 0x9ABCDEF0
#Malicious address
num3: .word 0x12345678
num4: .word 0xDEADBEEF


.text
main:
    lw a0, num2
    lw a1, num1
    lw a2, num4
    lw a3, num3
    xor a0, a0, a2
    xor a1, a1, a3
    jal ra, count_leading_zeros
    
    #Exit program
    li a7, 10
    ecall
    
count_leading_zeros:
    addi sp, sp, -24
    sw ra, 16(sp)
    sw a0, 8(sp)
    sw a1, 0(sp)
    # Prepare two registers for storing argument x
    # Arguments: a0 = x_low (lower 32 bits of x)
    #            a1 = x_high (upper 32 bits of x)
    # Return value: a0 = number of leading zeros
    
    # Initialize the x as input value
    add a0, a0, x0           # a0 = x_low
    add a1, a1, x0           # a1 = x_high
    addi t0, x0, 32          # t0 = 32
    addi t1, x0, 1           # t1 = 1, 2, 4, 8, 16, 32 for each iteration
loop: # x |= (x >> n) 
    sub t2, t0, t1           # t2 = 31, 30, 28, 24, 16, 0 for each iteration
    sll a3, a1, t2      #put the shift value from x_high to correct position
    srl a2, a0, t1           # shift right t1 bits in x_low
    or a2, a2, a3            # add the shift value from x_high to x_low
    or a0, a0, a2            # or x_low
    srl a2, a1, t1           # shift x_high
    or a1, a1, a2            # or x_high
    slli t1, t1, 1
    bge t0, t1, loop
    
count_ones: # Count ones (population count)
    # x -= ((x >> 1) & 0x5555555555555555)
    slli a3, a1, 31          #put the shift value from x_high to correct position
    srli a2, a0, 1           # shift right 1 bit in x_low
    or a2, a2, a3
    srli a4, a1, 1           #shift right 1 bit in x_high
    li a7, 0x55555555
    add t0, x0, a7
    and a2, a2, t0
    and a4, a4, t0
    # x = a1 a0 - a4 a2
    bge a2, a0, sub           # a5 = 1 when a0 < a2
    sub a0, a0, a2
    sub a1, a1, a4
    #sub a1, a1, a5
    
    # x = ((x >> 2) & 0x3333333333333333) + (x & 0x3333333333333333)
    slli a3, a1, 30     #put the shift value from x_high to correct position
    srli a2, a0, 2           # shift right 2 bits in x_low
    or a2, a2, a3
    srli a4, a1, 2           #shift right 2 bits in x_high
    li a7, 0x33333333
    add t0, x0, a7
    and a2, a2, t0       # lower 32 bits of ((x >> 2) & 0x3333333333333333)
    and a4, a4, t0       # higher 32 bits of ((x >> 2) & 0x3333333333333333)
    and a0, a0, t0       # lower 32 bits of (x & 0x3333333333333333)
    and a1, a1, t0       # higher 32 bits of (x & 0x3333333333333333)
    # x = a4 a2 + a1 a0
    add a0, a0, a2
    slt a5, a0, a2           # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # x = ((x >> 4) + x) & 0x0f0f0f0f0f0f0f0f
    slli a3, a1, 28     #put the shift value from x_high to correct position
    srli a2, a0, 4      # shift right 4 bits in x_low
    or a2, a2, a3
    srli a4, a1, 4      # shift right 4 bits in x_high
    # add a4 a2 and a1 a0. ((x >> 4) + x)
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    # a1 a0 & 0x0f0f0f0f0f0f0f0f
    li a7, 0x0f0f0f0f
    add t0, x0, a7
    and a0, a0, t0
    and a1, a1, t0
    
    # x += (x >> 8)
    slli a3, a1, 24     #put the shift value from x_high to correct position
    srli a2, a0, 8      # shift right 4 bits in x_low
    or a2, a2, a3
    srli a4, a1, 8      #shift right 4 bits in x_high
    # x = a1 a0 + a4 a2
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # x += (x >> 16)
    slli a3, a1, 16     #put the shift value from x_high to correct position
    srli a2, a0, 16     # shift right 4 bits in x_low
    or a2, a2, a3
    srli a4, a1, 16     #shift right 4 bits in x_high
    # x = a1 a0 + a4 a2
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # x += (x >> 32)
    slli a3, a1, 0
    li a7, 32      #put the shift value from x_high to correct position
    srl a2, a0, a7 
    or a2, a2, a3
    srl a4, a1, s7 
    # x = a1 a0 + a4 a2
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # (64 - (x & 0x7F))
    addi t0, x0, 64
    andi a0, a0, 0x7f
    sub a0, t0, a0      # a0 represent the number of leading zeros
    lw ra, 16(sp)
    addi sp, sp, 24
    ret
sub:
    addi a1, a1, -1
    li a7, 0xffffffff
    sub a7, a7, a2
    addi a7, a7, 1
    add a0, a7, a0
    sub a1, a1, a4
        sub a0, a0, a2
    sub a1, a1, a4
    #sub a1, a1, a5
    
    # x = ((x >> 2) & 0x3333333333333333) + (x & 0x3333333333333333)
    slli a3, a1, 30     #put the shift value from x_high to correct position
    srli a2, a0, 2           # shift right 2 bits in x_low
    or a2, a2, a3
    srli a4, a1, 2           #shift right 2 bits in x_high
    li a7, 0x33333333
    add t0, x0, a7
    and a2, a2, t0       # lower 32 bits of ((x >> 2) & 0x3333333333333333)
    and a4, a4, t0       # higher 32 bits of ((x >> 2) & 0x3333333333333333)
    and a0, a0, t0       # lower 32 bits of (x & 0x3333333333333333)
    and a1, a1, t0       # higher 32 bits of (x & 0x3333333333333333)
    # x = a4 a2 + a1 a0
    add a0, a0, a2
    slt a5, a0, a2           # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # x = ((x >> 4) + x) & 0x0f0f0f0f0f0f0f0f
    slli a3, a1, 28     #put the shift value from x_high to correct position
    srli a2, a0, 4      # shift right 4 bits in x_low
    or a2, a2, a3
    srli a4, a1, 4      # shift right 4 bits in x_high
    # add a4 a2 and a1 a0. ((x >> 4) + x)
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    # a1 a0 & 0x0f0f0f0f0f0f0f0f
    li a7, 0x0f0f0f0f
    add t0, x0, a7
    and a0, a0, t0
    and a1, a1, t0
    
    # x += (x >> 8)
    slli a3, a1, 24     #put the shift value from x_high to correct position
    srli a2, a0, 8      # shift right 4 bits in x_low
    or a2, a2, a3
    srli a4, a1, 8      #shift right 4 bits in x_high
    # x = a1 a0 + a4 a2
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # x += (x >> 16)
    slli a3, a1, 16     #put the shift value from x_high to correct position
    srli a2, a0, 16     # shift right 4 bits in x_low
    or a2, a2, a3
    srli a4, a1, 16     #shift right 4 bits in x_high
    # x = a1 a0 + a4 a2
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # x += (x >> 32)
    slli a3, a1, 0
    li a7, 32      #put the shift value from x_high to correct position
    srl a2, a0, a7 
    or a2, a2, a3
    srl a4, a1, s7 
    # x = a1 a0 + a4 a2
    add a0, a0, a2
    slt a5, a0, a2      # a5 = 1 when a0 < a2
    add a1, a1, a4
    add a1, a1, a5
    
    # (64 - (x & 0x7F))
    addi t0, x0, 64
    andi a0, a0, 0x7f
    sub a0, t0, a0      # a0 represent the number of leading zeros
    lw ra, 16(sp)
    addi sp, sp, 24
    ret
    
    
    

        