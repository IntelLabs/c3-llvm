// RUN: %check_clang_tidy %s misc-c3-struct-buf-tripwires %t


struct my_struct {
	int a;
	char b[16];
	int c;
	char d[16];
	int e;
};

struct my_struct_ok {
	int a;
	char b[16];
	char d[16];
    int c;
	int e;
};
