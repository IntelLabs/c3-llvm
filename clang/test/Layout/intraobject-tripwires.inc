#include <stddef.h>
#include <stdint.h>

#define TRIPWIRE_SIZE 8
#define ALIGNMENT 8

// The functions in this file statically check the offset of each struct member
// in different configurations of tripwire insertion. The checks use both the
// offsetof() function and hardcoded offsets. If both agree, then offsetof()
// has been successfully affected by tripwire insertion. The functions also
// check the total size of the struct depending on configuration.

int
run_00(void)
{
  // Expected storage layout
  //
  // None:
  // Attr:   0x00     0x08     0x10     0x18(24)
  //        +--------+--------+--------+
  //        |   m1   |   m2   |   m3   |
  //        +--------+--------+--------+
  //
  // All:    0x00     0x08     0x10     0x18     0x20     0x28(40)
  //        +--------+--------+--------+--------+--------+
  //        |   m1   |tripwire|   m2   |tripwire|   m3   |
  //        +--------+--------+--------+--------+--------+
  //
  typedef struct
  {
    uint64_t m1;
    uint8_t m2[8];
    uint64_t m3;
  } st_t;

  st_t data;

  _Static_assert(offsetof(st_t, m1) == 0x00);

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1)));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2)));
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1) + TRIPWIRE_SIZE));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2) + TRIPWIRE_SIZE));
#endif

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == 0x08);
  _Static_assert(offsetof(st_t, m3) == 0x10);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == 0x10);
  _Static_assert(offsetof(st_t, m3) == 0x20);
#endif

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(sizeof(st_t) == 0x18);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(sizeof(st_t) == 0x28);
#endif

  return 0;
}

int
run_01(void)
{
  // Expected storage layout
  //
  // None:
  // Attr:   0x00 0x04     0x0c 0x10(16)
  //        +----+--------+----+
  //        | m1 |   m2   | m3 |
  //        +----+--------+----+
  //
  // All:    0x00 0x04 0x08     0x10     0x18     0x20 0x24(36)
  //        +----+----+--------+--------+--------+----+
  //        | m1 |xxxx|tripwire|   m2   |tripwire| m3 |
  //        +----+----+--------+--------+--------+----+
  //              ~~~~
  //                 ^ padding
  //
  typedef struct
  {
    uint32_t m1;
    uint8_t m2[8];
    uint32_t m3;
  } st_t;

  st_t data;

  _Static_assert(offsetof(st_t, m1) == 0x00);

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1)));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2)));
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + (sizeof(data.m1) + ALIGNMENT - sizeof(data.m1)) + TRIPWIRE_SIZE));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2) + TRIPWIRE_SIZE));
#endif

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == 0x04);
  _Static_assert(offsetof(st_t, m3) == 0x0C);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == 0x10);
  _Static_assert(offsetof(st_t, m3) == 0x20);
#endif

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(sizeof(st_t) == 0x10);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(sizeof(st_t) == 0x24);
#endif

  return 0;
}

int
run_02(void)
{
  // Expected storage layout
  //
  // None:   0x00     0x08     0x10     0x18(24)
  //        +--------+--------+--------+
  //        |   m1   |   m2   |   m3   |
  //        +--------+--------+--------+
  //
  // All:
  // Attr:   0x00     0x08     0x10     0x18     0x20     0x28(40)
  //        +--------+--------+--------+--------+--------+
  //        |   m1   |tripwire|   m2   |tripwire|   m3   |
  //        +--------+--------+--------+--------+--------+
  //
  typedef struct
  {
    uint64_t m1;
    uint8_t m2[8] __attribute__((tripwires));
    uint64_t m3;
  } st_t;

  st_t data;

  _Static_assert(offsetof(st_t, m1) == 0x00);

#if defined TRIPWIRES_NONE
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1)));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2)));
#endif
#if defined TRIPWIRES_ALL || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1) + TRIPWIRE_SIZE));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2) + TRIPWIRE_SIZE));
#endif

#if defined TRIPWIRES_NONE
  _Static_assert(offsetof(st_t, m2) == 0x08);
  _Static_assert(offsetof(st_t, m3) == 0x10);
#endif
#if defined TRIPWIRES_ALL || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == 0x10);
  _Static_assert(offsetof(st_t, m3) == 0x20);
#endif

#if defined TRIPWIRES_NONE
  _Static_assert(sizeof(st_t) == 0x18);
#endif
#if defined TRIPWIRES_ALL || defined TRIPWIRES_ATTR
  _Static_assert(sizeof(st_t) == 0x28);
#endif

  return 0;
}

int
run_03(void)
{
  // Expected storage layout
  //
  // None:
  // All:
  // Attr:   0x00     0x08     0x10     0x18(24)
  //        +--------+--------+--------+
  //        |   m1   |   m2   |   m3   |
  //        +--------+--------+--------+
  //
  typedef struct
  {
    uint64_t m1;
    uint8_t m2[8] __attribute__((notripwires));
    uint64_t m3;
  } st_t;

  st_t data;

  _Static_assert(offsetof(st_t, m1) == 0x00);

  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1)));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2)));

  _Static_assert(offsetof(st_t, m2) == 0x08);
  _Static_assert(offsetof(st_t, m3) == 0x10);

  _Static_assert(sizeof(st_t) == 0x18);

  return 0;
}

int
run_04(void)
{
  // Expected storage layout
  //
  // None:   0x00     0x08     0x10     0x18     0x20     0x28(40)
  //        +--------+--------+--------+--------+--------+
  //        |   m1   |   m2   |   m3   |   m4   |   m5   |
  //        +--------+--------+--------+--------+--------+
  //
  // All:    0x00     0x08     0x10     0x18     0x20     0x28     0x30     0x38     0x40     0x48(72)
  //        +--------+--------+--------+--------+--------+--------+--------+--------+--------+
  //        |   m1   |tripwire|   m2   |tripwire|   m3   |tripwire|   m4   |tripwire|   m5   |
  //        +--------+--------+--------+--------+--------+--------+--------+--------+--------+
  //
  // Attr:   0x00     0x08     0x10     0x18     0x20     0x28     0x30     0x38(56)
  //        +--------+--------+--------+--------+--------+--------+--------+
  //        |   m1   |   m2   |   m3   |tripwire|   m4   |tripwire|   m5   |
  //        +--------+--------+--------+--------+--------+--------+--------+
  //
  typedef struct
  {
    uint64_t m1;
    uint8_t m2[8];
    uint64_t m3;
    uint8_t m4[8] __attribute__((tripwires));
    uint64_t m5;
  } st_t;

  st_t data;

  _Static_assert(offsetof(st_t, m1) == 0x00);

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1)));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2)));
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1) + TRIPWIRE_SIZE));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2) + TRIPWIRE_SIZE));
#endif
#if defined TRIPWIRES_NONE
  _Static_assert(offsetof(st_t, m4) == (offsetof(st_t, m3) + sizeof(data.m3)));
  _Static_assert(offsetof(st_t, m5) == (offsetof(st_t, m4) + sizeof(data.m4)));
#endif
#if defined TRIPWIRES_ALL || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m4) == (offsetof(st_t, m3) + sizeof(data.m3) + TRIPWIRE_SIZE));
  _Static_assert(offsetof(st_t, m5) == (offsetof(st_t, m4) + sizeof(data.m4) + TRIPWIRE_SIZE));
#endif

#if defined TRIPWIRES_NONE
  _Static_assert(offsetof(st_t, m2) == 0x08);
  _Static_assert(offsetof(st_t, m3) == 0x10);
  _Static_assert(offsetof(st_t, m4) == 0x18);
  _Static_assert(offsetof(st_t, m5) == 0x20);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == 0x10);
  _Static_assert(offsetof(st_t, m3) == 0x20);
  _Static_assert(offsetof(st_t, m4) == 0x30);
  _Static_assert(offsetof(st_t, m5) == 0x40);
#endif
#if defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == 0x08);
  _Static_assert(offsetof(st_t, m3) == 0x10);
  _Static_assert(offsetof(st_t, m4) == 0x20);
  _Static_assert(offsetof(st_t, m5) == 0x30);
#endif

#if defined TRIPWIRES_NONE
  _Static_assert(sizeof(st_t) == 0x28);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(sizeof(st_t) == 0x48);
#endif
#if defined TRIPWIRES_ATTR
  _Static_assert(sizeof(st_t) == 0x38);
#endif

  return 0;
}

int
run_05(void)
{
  // Expected storage layout
  //
  // None:
  // Attr:   0x00     0x08     0x10     0x18     0x20     0x28(40)
  //        +--------+--------+--------+--------+--------+
  //        |   m1   |   m2   |   m3   |   m4   |   m5   |
  //        +--------+--------+--------+--------+--------+
  //
  // All:    0x00     0x08     0x10     0x18     0x20     0x28     0x30     0x38(56)
  //        +--------+--------+--------+--------+--------+--------+--------+
  //        |   m1   |tripwire|   m2   |tripwire|   m3   |   m4   |   m5   |
  //        +--------+--------+--------+--------+--------+--------+--------+
  //
  typedef struct
  {
    uint64_t m1;
    uint8_t m2[8];
    uint64_t m3;
    uint8_t m4[8] __attribute__((notripwires));
    uint64_t m5;
  } st_t;

  st_t data;

  _Static_assert(offsetof(st_t, m1) == 0x00);

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1)));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2)));
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == (offsetof(st_t, m1) + sizeof(data.m1) + TRIPWIRE_SIZE));
  _Static_assert(offsetof(st_t, m3) == (offsetof(st_t, m2) + sizeof(data.m2) + TRIPWIRE_SIZE));
#endif
  _Static_assert(offsetof(st_t, m4) == (offsetof(st_t, m3) + sizeof(data.m3)));
  _Static_assert(offsetof(st_t, m5) == (offsetof(st_t, m4) + sizeof(data.m4)));

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(offsetof(st_t, m2) == 0x08);
  _Static_assert(offsetof(st_t, m3) == 0x10);
  _Static_assert(offsetof(st_t, m4) == 0x18);
  _Static_assert(offsetof(st_t, m5) == 0x20);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(offsetof(st_t, m2) == 0x10);
  _Static_assert(offsetof(st_t, m3) == 0x20);
  _Static_assert(offsetof(st_t, m4) == 0x28);
  _Static_assert(offsetof(st_t, m5) == 0x30);
#endif

#if defined TRIPWIRES_NONE || defined TRIPWIRES_ATTR
  _Static_assert(sizeof(st_t) == 0x28);
#endif
#if defined TRIPWIRES_ALL
  _Static_assert(sizeof(st_t) == 0x38);
#endif

  return 0;
}

#define EXEC(x) \
  if (x) \
    return 1;

int
main(void)
{
  EXEC(run_00())
  EXEC(run_01())
  EXEC(run_02())
  EXEC(run_03())
  EXEC(run_04())
  EXEC(run_05())

  return 0;
}
