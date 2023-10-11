// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * This file was automatically created by syscalls-bumper (https://github.com/falcosecurity/syscalls-bumper).")
 * DO NOT EDIT THIS FILE MANUALLY.")
 */

#include "ppm_events_public.h"

/*
 * This table is used by drivers when receiving a 32bit syscall.
 * It is needed to convert a 32bit syscall (the array index) to a 64bit syscall value.
 * NOTE: some syscalls might be unavailable on x86_64; their value will be set to -1.
 * Some unavailable syscalls are identical to a compatible x86_64 syscall; in those cases,
 * we use the compatible x86_64 syscall, eg: mmap2 -> mmap.
 */
const int g_ia32_64_map[SYSCALL_TABLE_SIZE] = {
	[396] = 31,
	[315] = 276,
	[286] = 248,
	[394] = 66,
	[5] = 2,
	[167] = 178,
	[302] = 264,
	[399] = 68,
	[84] = -1, // ia32 only: oldlstat
	[107] = 6,
	[79] = 164,
	[281] = 244,
	[166] = -1, // ia32 only: vm86
	[162] = 35,
	[278] = 241,
	[127] = 174,
	[14] = 133,
	[209] = -1, // ia32 only: getresuid32
	[3] = 0,
	[319] = 281,
	[244] = 211,
	[221] = -1, // ia32 only: fcntl64
	[85] = 89,
	[159] = 146,
	[263] = 226,
	[96] = 140,
	[416] = -1, // ia32 only: io_pgetevents_time64
	[365] = 55,
	[293] = 255,
	[201] = -1, // ia32 only: geteuid32
	[438] = 438,
	[321] = 282,
	[307] = 269,
	[183] = 79,
	[353] = 316,
	[81] = 116,
	[300] = -1, // ia32 only: fstatat64
	[132] = 121,
	[199] = -1, // ia32 only: getuid32
	[170] = 119,
	[106] = 4,
	[51] = 163,
	[433] = 433,
	[129] = 176,
	[19] = 8,
	[61] = 161,
	[406] = -1, // ia32 only: clock_getres_time64
	[442] = 442,
	[36] = 162,
	[325] = 286,
	[55] = 72,
	[246] = 207,
	[15] = 90,
	[447] = 447,
	[25] = -1, // ia32 only: stime
	[231] = 193,
	[444] = 444,
	[351] = 314,
	[398] = 67,
	[425] = 425,
	[317] = 279,
	[236] = 198,
	[350] = 313,
	[349] = 312,
	[20] = 39,
	[196] = -1, // ia32 only: lstat64
	[274] = 237,
	[168] = 7,
	[379] = 328,
	[451] = 451,
	[207] = -1, // ia32 only: fchown32
	[309] = 271,
	[134] = -1, // ia32 only: bdflush
	[296] = 258,
	[67] = -1, // ia32 only: sigaction
	[271] = 235,
	[264] = 227,
	[105] = 36,
	[80] = 115,
	[247] = 208,
	[418] = -1, // ia32 only: mq_timedsend_time64
	[180] = 17,
	[287] = 249,
	[160] = 147,
	[8] = 85,
	[197] = -1, // ia32 only: fstat64
	[303] = 265,
	[280] = 243,
	[186] = 131,
	[185] = 126,
	[422] = -1, // ia32 only: futex_time64
	[28] = -1, // ia32 only: oldfstat
	[382] = 331,
	[417] = -1, // ia32 only: recvmmsg_time64
	[115] = 168,
	[252] = 231,
	[76] = 97,
	[318] = 309,
	[414] = -1, // ia32 only: ppoll_time64
	[131] = 179,
	[182] = 92,
	[266] = 229,
	[126] = -1, // ia32 only: sigprocmask
	[200] = -1, // ia32 only: getgid32
	[121] = 171,
	[176] = 127,
	[393] = 64,
	[210] = -1, // ia32 only: setresgid32
	[213] = -1, // ia32 only: setuid32
	[373] = 48,
	[328] = 290,
	[9] = 86,
	[421] = -1, // ia32 only: rt_sigtimedwait_time64
	[408] = -1, // ia32 only: timer_gettime64
	[255] = 233,
	[324] = 285,
	[154] = 142,
	[383] = 332,
	[220] = 217,
	[369] = 44,
	[198] = -1, // ia32 only: lchown32
	[34] = -1, // ia32 only: nice
	[381] = 330,
	[284] = 247,
	[49] = 107,
	[363] = 50,
	[64] = 110,
	[395] = 29,
	[448] = 448,
	[314] = 277,
	[370] = 46,
	[226] = 188,
	[73] = -1, // ia32 only: sigpending
	[133] = 81,
	[385] = 333,
	[360] = 53,
	[92] = 76,
	[120] = 56,
	[155] = 143,
	[227] = 189,
	[323] = 284,
	[150] = 149,
	[158] = 24,
	[262] = 225,
	[27] = 37,
	[234] = 196,
	[358] = 322,
	[291] = 253,
	[241] = 203,
	[420] = -1, // ia32 only: semtimedop_time64
	[139] = 123,
	[359] = 41,
	[62] = 136,
	[94] = 91,
	[355] = 318,
	[452] = 452,
	[304] = 266,
	[128] = 175,
	[248] = 209,
	[39] = 83,
	[184] = 125,
	[93] = 77,
	[181] = 18,
	[254] = 213,
	[77] = 98,
	[38] = 82,
	[344] = 306,
	[237] = 199,
	[89] = -1, // ia32 only: readdir
	[148] = 75,
	[270] = 234,
	[23] = 105,
	[30] = 132,
	[205] = -1, // ia32 only: getgroups32
	[172] = 157,
	[401] = 70,
	[46] = 106,
	[104] = 38,
	[346] = 308,
	[366] = 54,
	[376] = 325,
	[192] = 9, // NOTE: syscall unmapped on x86_64, forcefully mapped to compatible syscall. See syscalls-bumper bumpIA32to64Map() call.
	[261] = 224,
	[316] = 278,
	[63] = 33,
	[368] = 52,
	[1] = 60,
	[229] = 191,
	[258] = 218,
	[219] = 28,
	[109] = -1, // ia32 only: olduname
	[21] = 165,
	[42] = 22,
	[0] = 219,
	[2] = 57,
	[240] = 202,
	[371] = 45,
	[215] = -1, // ia32 only: setfsuid32
	[409] = -1, // ia32 only: timer_settime64
	[86] = 134,
	[78] = 96,
	[288] = 250,
	[206] = -1, // ia32 only: setgroups32
	[68] = -1, // ia32 only: sgetmask
	[446] = 446,
	[375] = 324,
	[82] = 23,
	[450] = 450,
	[233] = 195,
	[361] = 49,
	[343] = 305,
	[428] = 428,
	[65] = 111,
	[279] = 242,
	[380] = 329,
	[238] = 200,
	[4] = 1,
	[308] = 270,
	[69] = -1, // ia32 only: ssetmask
	[407] = -1, // ia32 only: clock_nanosleep_time64
	[40] = 84,
	[174] = 13,
	[157] = 145,
	[70] = 113,
	[250] = 221,
	[145] = 19,
	[333] = 295,
	[225] = 187,
	[320] = 280,
	[339] = 301,
	[331] = 293,
	[230] = 192,
	[116] = 99,
	[439] = 439,
	[269] = -1, // ia32 only: fstatfs64
	[47] = 104,
	[165] = 118,
	[445] = 445,
	[97] = 141,
	[119] = -1, // ia32 only: sigreturn
	[362] = 42,
	[272] = -1, // ia32 only: fadvise64_64
	[204] = -1, // ia32 only: setregid32
	[149] = 156,
	[6] = 3,
	[336] = 298,
	[100] = 138,
	[101] = 173,
	[301] = 263,
	[374] = 323,
	[7] = -1, // ia32 only: waitpid
	[253] = 212,
	[179] = 130,
	[306] = 268,
	[449] = 449,
	[372] = 47,
	[412] = -1, // ia32 only: utimensat_time64
	[143] = 73,
	[152] = 151,
	[136] = 135,
	[124] = 159,
	[384] = 158,
	[112] = -1, // ia32 only: idle
	[171] = 120,
	[224] = 186,
	[342] = 304,
	[217] = 155,
	[335] = 297,
	[260] = 223,
	[41] = 32,
	[54] = 16,
	[367] = 51,
	[208] = -1, // ia32 only: setresuid32
	[289] = 251,
	[277] = 240,
	[178] = 129,
	[11] = 59,
	[275] = 239,
	[345] = 307,
	[99] = 137,
	[410] = -1, // ia32 only: timerfd_gettime64
	[283] = 246,
	[337] = 299,
	[348] = 311,
	[177] = 128,
	[267] = 230,
	[430] = 430,
	[151] = 150,
	[249] = 210,
	[125] = 10,
	[347] = 310,
	[326] = 287,
	[338] = 300,
	[424] = 424,
	[13] = 201,
	[411] = -1, // ia32 only: timerfd_settime64
	[37] = 62,
	[75] = 160,
	[202] = -1, // ia32 only: getegid32
	[146] = 20,
	[45] = 12,
	[95] = 93,
	[59] = -1, // ia32 only: oldolduname
	[74] = 170,
	[60] = 95,
	[357] = 321,
	[123] = 154,
	[203] = -1, // ia32 only: setreuid32
	[190] = 58,
	[110] = 172,
	[29] = 34,
	[216] = -1, // ia32 only: setfsgid32
	[33] = 21,
	[211] = -1, // ia32 only: getresgid32
	[114] = 61,
	[402] = 71,
	[341] = 303,
	[135] = 139,
	[103] = 103,
	[130] = 177,
	[50] = 108,
	[434] = 434,
	[173] = 15,
	[102] = -1, // ia32 only: socketcall
	[377] = 326,
	[147] = 124,
	[141] = 78,
	[276] = 238,
	[243] = 205,
	[57] = 109,
	[431] = 431,
	[228] = 190,
	[299] = 261,
	[290] = 252,
	[443] = 443,
	[66] = 112,
	[397] = 30,
	[322] = 283,
	[441] = 441,
	[432] = 432,
	[257] = 216,
	[10] = 87,
	[214] = -1, // ia32 only: setgid32
	[122] = 63,
	[191] = -1, // ia32 only: ugetrlimit
	[52] = 166,
	[48] = -1, // ia32 only: signal
	[268] = -1, // ia32 only: statfs64
	[282] = 245,
	[332] = 294,
	[245] = 206,
	[437] = 437,
	[329] = 291,
	[117] = -1, // ia32 only: ipc
	[356] = 319,
	[83] = 88,
	[354] = 317,
	[87] = 167,
	[118] = 74,
	[400] = 69,
	[435] = 435,
	[24] = 102,
	[43] = 100,
	[111] = 153,
	[212] = -1, // ia32 only: chown32
	[265] = 228,
	[298] = 260,
	[327] = 289,
	[436] = 436,
	[330] = 292,
	[169] = 180,
	[235] = 197,
	[12] = 80,
	[405] = -1, // ia32 only: clock_adjtime64
	[164] = 117,
	[187] = 40,
	[138] = 122,
	[18] = -1, // ia32 only: oldstat
	[72] = -1, // ia32 only: sigsuspend
	[364] = 288,
	[403] = -1, // ia32 only: clock_gettime64
	[259] = 222,
	[22] = -1, // ia32 only: umount
	[91] = 11,
	[71] = 114,
	[239] = -1, // ia32 only: sendfile64
	[294] = 256,
	[163] = 25,
	[195] = -1, // ia32 only: stat64
	[108] = 5,
	[426] = 426,
	[88] = 169,
	[194] = -1, // ia32 only: ftruncate64
	[90] = 9,
	[242] = 204,
	[156] = 144,
	[429] = 429,
	[378] = 327,
	[427] = 427,
	[295] = 257,
	[175] = 14,
	[404] = -1, // ia32 only: clock_settime64
	[292] = 254,
	[153] = 152,
	[305] = 267,
	[193] = -1, // ia32 only: truncate64
	[310] = 272,
	[16] = 94,
	[144] = 26,
	[419] = -1, // ia32 only: mq_timedreceive_time64
	[340] = 302,
	[440] = 440,
	[313] = 275,
	[113] = -1, // ia32 only: vm86old
	[256] = 232,
	[312] = 274,
	[26] = 101,
	[311] = 273,
	[188] = 181,
	[218] = 27,
	[334] = 296,
	[413] = -1, // ia32 only: pselect6_time64
	[386] = 334,
	[232] = 194,
	[297] = 259,
	[352] = 315,
	[161] = 148,
	[423] = -1, // ia32 only: sched_rr_get_interval_time64
	[140] = -1, // ia32 only: _llseek
	[142] = -1, // ia32 only: _newselect
};
