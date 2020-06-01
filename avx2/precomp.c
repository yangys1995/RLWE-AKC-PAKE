#include "inttypes.h"
#include "ntt.h"
#include "params_pak.h"

int32_t omegas[PARAM_N/2]		= {1,10810,7143,4043,10984,722,5736,8155,3542,8785,9744,3621,10643,1212,3195,5860,7468,2639,9664,11340,11726,9314,9283,9545,5728,7698,5023,5828,8961,6512,7311,1351,2319,11119,11334,11499,9088,3014,5086,10963,4846,9542,9154,3712,4805,8736,11227,9995,3091,12208,7969,11289,9326,7393,9238,2366,11112,8034,10654,9521,12149,10436,7678,11563,1260,4388,4632,6534,2426,334,1428,1696,2013,9000,729,3241,2881,3284,7197,10200,8595,7110,10530,8582,3382,11934,9741,8058,3637,3459,145,6747,9558,8357,7399,6378,9447,480,1022,9,9821,339,5791,544,10616,4278,6958,7300,8112,8705,1381,9764,11336,8541,827,5767,2476,118,2197,7222,3949,8993,4452,2396,7935,130,2837,6915,2401,442,7188,11222,390,773,8456,3778,354,4861,9377,5698,5012,9808,2859,11244,1017,7404,1632,7205,27,9223,8526,10849,1537,242,4714,8146,9611,3704,5019,11744,1002,5011,5088,8005,7313,10682,8509,11414,9852,3646,6022,2987,9723,10102,6250,9867,11224,2143,11885,7644,1168,5277,11082,3248,493,8193,6845,2381,7952,11854,1378,1912,2166,3915,12176,7370,12129,3149,12286,4437,3636,4938,5291,2704,10863,7635,1663,10512,3364,1689,4057,9018,9442,7875,2174,4372,7247,9984,4053,2645,5195,9509,7394,1484,9042,9603,8311,9320,9919,2865,5332,3510,1630,10163,5407,3186,11136,9405,10040,8241,9890,8889,7098,9153,9289,671,3016,243,6730,420,10111,1544,3985,4905,3531,476,49,1263,5915,1483,9789,10800,10706,6347,1512,350,10474,5383,5369,10232,9087,4493,9551,6421,6554,2655,9280,1693,174,723,10314,8532,347,2925,8974,11863,1858,4754,3030,4115,2361,10446,2908,218,3434,8760,3963,576,6142,9842,1954,10238,9407,10484,3991,8320,9522,156,2281,5876,10258,5333,3772,418,5908,11836,5429,7515,7552,1293,295,6099,5766,652,8273,4077,8527,9370,325,10885,11143,11341,5990,1159,8561,8240,3329,4298,12121,2692,5961,7183,10327,1594,6167,9734,7105,11089,1360,3956,6170,5297,8210,11231,922,441,1958,4322,1112,2078,4046,709,9139,1319,4240,8719,6224,11454,2459,683,3656,12225,10723,5782,9341,9786,9166,10542,9235,6803,7856,6370,3834,7032,7048,9369,8120,9162,6821,1010,8807,787,5057,4698,4780,8844,12097,1321,4912,10240,677,6415,6234,8953,1323,9523,12237,3174,1579,11858,9784,5906,3957,9450,151,10162,12231,12048,3532,11286,1956,7280,11404,6281,3477,6608,142,11184,9445,3438,11314,4212,9260,6695,4782,5886,8076,504,2302,11684,11868,8209,3602,6068,8689,3263,6077,7665,7822,7500,6752,4749,4449,6833,12142,8500,6118,8471,1190,9606,3860,5445,7753,11239,5079,9027,2169,11767,7965,4916,8214,5315,11011,9945,1973,6715,8775,11248,5925,11271,654,3565,1702,1987,6760,5206,3199,12233,6136,6427,6874,8646,4948,6152,400,10561,5339,5446,3710,6093,468,8301,316,11907,10256,8291,3879,1922,10930,6854,973,11035};


int32_t omegas_inv[PARAM_N/2]	= {1,1479,8246,5146,4134,6553,11567,1305,6429,9094,11077,1646,8668,2545,3504,8747,10938,4978,5777,3328,6461,7266,4591,6561,2744,3006,2975,563,949,2625,9650,4821,726,4611,1853,140,2768,1635,4255,1177,9923,3051,4896,2963,1000,4320,81,9198,2294,1062,3553,7484,8577,3135,2747,7443,1326,7203,9275,3201,790,955,1170,9970,5374,9452,12159,4354,9893,7837,3296,8340,5067,10092,12171,9813,6522,11462,3748,953,2525,10908,3584,4177,4989,5331,8011,1673,11745,6498,11950,2468,12280,11267,11809,2842,5911,4890,3932,2731,5542,12144,8830,8652,4231,2548,355,8907,3707,1759,5179,3694,2089,5092,9005,9408,9048,11560,3289,10276,10593,10861,11955,9863,5755,7657,7901,11029,11813,8758,7384,8304,10745,2178,11869,5559,12046,9273,11618,3000,3136,5191,3400,2399,4048,2249,2884,1153,9103,6882,2126,10659,8779,6957,9424,2370,2969,3978,2686,3247,10805,4895,2780,7094,9644,8236,2305,5042,7917,10115,4414,2847,3271,8232,10600,8925,1777,10626,4654,1426,9585,6998,7351,8653,7852,3,9140,160,4919,113,8374,10123,10377,10911,435,4337,9908,5444,4096,11796,9041,1207,7012,11121,4645,404,10146,1065,2422,6039,2187,2566,9302,6267,8643,2437,875,3780,1607,4976,4284,7201,7278,11287,545,7270,8585,2678,4143,7575,12047,10752,1440,3763,3066,12262,5084,10657,4885,11272,1045,9430,2481,7277,6591,2912,7428,11935,8511,3833,11516,11899,1067,5101,11847,9888,1254,11316,5435,1359,10367,8410,3998,2033,382,11973,3988,11821,6196,8579,6843,6950,1728,11889,6137,7341,3643,5415,5862,6153,56,9090,7083,5529,10302,10587,8724,11635,1018,6364,1041,3514,5574,10316,2344,1278,6974,4075,7373,4324,522,10120,3262,7210,1050,4536,6844,8429,2683,11099,3818,6171,3789,147,5456,7840,7540,5537,4789,4467,4624,6212,9026,3600,6221,8687,4080,421,605,9987,11785,4213,6403,7507,5594,3029,8077,975,8851,2844,1105,12147,5681,8812,6008,885,5009,10333,1003,8757,241,58,2127,12138,2839,8332,6383,2505,431,10710,9115,52,2766,10966,3336,6055,5874,11612,2049,7377,10968,192,3445,7509,7591,7232,11502,3482,11279,5468,3127,4169,2920,5241,5257,8455,5919,4433,5486,3054,1747,3123,2503,2948,6507,1566,64,8633,11606,9830,835,6065,3570,8049,10970,3150,11580,8243,10211,11177,7967,10331,11848,11367,1058,4079,6992,6119,8333,10929,1200,5184,2555,6122,10695,1962,5106,6328,9597,168,7991,8960,4049,3728,11130,6299,948,1146,1404,11964,2919,3762,8212,4016,11637,6523,6190,11994,10996,4737,4774,6860,453,6381,11871,8517,6956,2031,6413,10008,12133,2767,3969,8298,1805,2882,2051,10335,2447,6147,11713,8326,3529,8855,12071,9381,1843,9928,8174,9259,7535,10431,426,3315,9364,11942,3757,1975,11566,12115,10596,3009,9634,5735,5868,2738,7796,3202,2057,6920,6906,1815,11939,10777,5942,1583,1489,2500,10806,6374,11026,12240};


int32_t psis_bitrev[PARAM_N]   = {1,10810,7143,4043,10984,722,5736,8155,3542,8785,9744,3621,10643,1212,3195,5860,7468,2639,9664,11340,11726,9314,9283,9545,5728,7698,5023,5828,8961,6512,7311,1351,2319,11119,11334,11499,9088,3014,5086,10963,4846,9542,9154,3712,4805,8736,11227,9995,3091,12208,7969,11289,9326,7393,9238,2366,11112,8034,10654,9521,12149,10436,7678,11563,1260,4388,4632,6534,2426,334,1428,1696,2013,9000,729,3241,2881,3284,7197,10200,8595,7110,10530,8582,3382,11934,9741,8058,3637,3459,145,6747,9558,8357,7399,6378,9447,480,1022,9,9821,339,5791,544,10616,4278,6958,7300,8112,8705,1381,9764,11336,8541,827,5767,2476,118,2197,7222,3949,8993,4452,2396,7935,130,2837,6915,2401,442,7188,11222,390,773,8456,3778,354,4861,9377,5698,5012,9808,2859,11244,1017,7404,1632,7205,27,9223,8526,10849,1537,242,4714,8146,9611,3704,5019,11744,1002,5011,5088,8005,7313,10682,8509,11414,9852,3646,6022,2987,9723,10102,6250,9867,11224,2143,11885,7644,1168,5277,11082,3248,493,8193,6845,2381,7952,11854,1378,1912,2166,3915,12176,7370,12129,3149,12286,4437,3636,4938,5291,2704,10863,7635,1663,10512,3364,1689,4057,9018,9442,7875,2174,4372,7247,9984,4053,2645,5195,9509,7394,1484,9042,9603,8311,9320,9919,2865,5332,3510,1630,10163,5407,3186,11136,9405,10040,8241,9890,8889,7098,9153,9289,671,3016,243,6730,420,10111,1544,3985,4905,3531,476,49,1263,5915,1483,9789,10800,10706,6347,1512,350,10474,5383,5369,10232,9087,4493,9551,6421,6554,2655,9280,1693,174,723,10314,8532,347,2925,8974,11863,1858,4754,3030,4115,2361,10446,2908,218,3434,8760,3963,576,6142,9842,1954,10238,9407,10484,3991,8320,9522,156,2281,5876,10258,5333,3772,418,5908,11836,5429,7515,7552,1293,295,6099,5766,652,8273,4077,8527,9370,325,10885,11143,11341,5990,1159,8561,8240,3329,4298,12121,2692,5961,7183,10327,1594,6167,9734,7105,11089,1360,3956,6170,5297,8210,11231,922,441,1958,4322,1112,2078,4046,709,9139,1319,4240,8719,6224,11454,2459,683,3656,12225,10723,5782,9341,9786,9166,10542,9235,6803,7856,6370,3834,7032,7048,9369,8120,9162,6821,1010,8807,787,5057,4698,4780,8844,12097,1321,4912,10240,677,6415,6234,8953,1323,9523,12237,3174,1579,11858,9784,5906,3957,9450,151,10162,12231,12048,3532,11286,1956,7280,11404,6281,3477,6608,142,11184,9445,3438,11314,4212,9260,6695,4782,5886,8076,504,2302,11684,11868,8209,3602,6068,8689,3263,6077,7665,7822,7500,6752,4749,4449,6833,12142,8500,6118,8471,1190,9606,3860,5445,7753,11239,5079,9027,2169,11767,7965,4916,8214,5315,11011,9945,1973,6715,8775,11248,5925,11271,654,3565,1702,1987,6760,5206,3199,12233,6136,6427,6874,8646,4948,6152,400,10561,5339,5446,3710,6093,468,8301,316,11907,10256,8291,3879,1922,10930,6854,973,11035,7,1936,845,3723,3154,5054,3285,7929,216,50,6763,769,767,8484,10076,4153,3120,6184,6203,5646,8348,3753,3536,5370,3229,4730,10583,3929,1282,8717,2021,9457,3944,4099,5604,6759,2171,8809,11024,3007,9344,5349,2633,1406,9057,11996,4855,8520,9348,11722,6627,5289,3837,2595,3221,4273,4050,7082,844,5202,11309,11607,4590,7207,8820,6138,7846,8871,4693,2338,9996,11872,1802,1555,5103,10398,7878,10699,1223,9955,11009,614,12265,10918,11385,9804,6742,7250,881,11924,1015,10362,5461,9343,2637,7779,4684,3360,7154,63,7302,2373,3670,3808,578,5368,11839,1944,7628,11779,9667,6903,5618,10631,5789,3502,5043,826,3090,1398,3065,1506,6586,4483,6389,910,7570,11538,4518,3094,1160,4820,2730,5411,10036,1868,2478,9449,4194,3019,10506,7211,7724,4974,7119,2672,11424,1279,189,3116,10526,2209,10759,1694,8420,7866,5832,1350,10555,8474,7014,10499,11038,6879,2035,1040,10407,6164,7519,944,5287,8620,6616,9269,6883,7624,4834,2712,9461,4352,8176,72,3840,10447,3451,8195,11048,4378,6508,9244,9646,1095,2873,2827,11498,2434,11169,9754,12268,6481,874,9988,170,6639,2307,4289,11641,12139,11259,11823,3821,1681,4649,5969,2929,6026,1573,8443,3793,6226,11787,5118,2602,10388,1849,5776,9021,3795,7988,7766,457,12281,11410,9696,982,10013,4218,4390,8835,8531,7785,778,530,2626,3578,4697,8823,1701,10243,2940,9332,10808,3317,9757,139,3332,343,8841,4538,10381,7078,1866,1208,7562,10584,2450,11873,814,716,10179,2164,6873,5412,8080,9011,6296,3515,11851,1218,5061,10753,10568,2429,8186,1373,9307,717,8700,8921,4227,4238,11677,8067,1526,11749,12164,3163,4032,6127,7449,1389,10221,4404,11943,3359,9084,5209,1092,3678,4265,10361,464,1826,2926,4489,9118,1136,3449,3708,9051,2065,5826,3495,4564,8755,3961,10533,4145,2275,2461,4267,5653,5063,8113,10771,8524,11014,5508,11113,6555,4860,1125,10844,11158,6302,6693,579,3889,9520,3114,6323,212,8314,4883,6454,3087,1417,5676,7784,2257,3744,4963,2528,9233,5102,11877,6701,6444,4924,4781,1014,11841,1327,3607,3942,7057,2717,60,3200,10754,5836,7723,2260,68,180,4138,7684,2689,10880,7070,204,5509,10821,8308,8882,463,10945,9247,9806,10235,4739,8038,6771,1226,9261,5216,11925,9929,11053,9272,7043,4475,3121,4705,1057,9689,11883,10602,146,5268,1403,1804,6094,7100,12050,9389,994,4554,4670,11777,5464,4906,3375,9998,8896,4335,7376,3528,3825,8054,9342,8307,636,5609,11667,10552,5672,4499,5598,3344,10397,8665,6565,10964,11260,10344,5959,10141,8330,5797,2442,1248,5115,4939,10975,1744,2894,8635,6599,9834,8342,338,3343,8170,1522,10138,12269,5002,4608,5163,4578,377,11914,1620,10453,11864,10104,11897,6085,8122,11251,11366,10058,6197,2800,193,506,1255,1392,5784,3276,8951,2212,9615,10347,8881,2575,1165,2776,11111,6811,3511};
int32_t psis_inv[PARAM_N]   = {12277,5265,9530,3117,5712,816,10650,3277,9246,4832,5957,851,10655,10300,3227,461,3577,511,73,1766,5519,2544,2119,7325,2802,5667,11343,3376,5749,6088,7892,2883,3923,2316,3842,4060,580,3594,2269,9102,6567,9716,1388,5465,7803,8137,2918,3928,9339,10112,11978,10489,3254,3976,568,8859,11799,12219,12279,10532,12038,8742,4760,680,8875,4779,7705,8123,2916,10950,6831,4487,641,10625,5029,2474,2109,5568,2551,2120,3814,4056,2335,10867,3308,11006,6839,977,10673,8547,1221,1930,7298,11576,8676,2995,3939,7585,11617,12193,5253,2506,358,8829,6528,11466,1638,234,1789,10789,6808,11506,8666,1238,3688,4038,4088,584,1839,7285,8063,4663,9444,10127,8469,4721,2430,9125,11837,1691,10775,6806,6239,6158,7902,4640,4174,5863,11371,3380,3994,11104,6853,979,3651,11055,6846,978,7162,9801,10178,1454,7230,4544,9427,8369,11729,12209,10522,10281,8491,1213,5440,9555,1365,195,3539,11039,1577,5492,11318,5128,11266,3365,7503,4583,7677,8119,4671,5934,7870,6391,913,1886,2025,5556,7816,11650,6931,9768,3151,9228,6585,7963,11671,6934,11524,6913,11521,5157,7759,2864,9187,3068,5705,815,1872,2023,289,5308,6025,7883,9904,4926,7726,8126,4672,2423,9124,3059,437,1818,7282,6307,901,7151,11555,8673,1239,177,5292,756,108,1771,253,8814,10037,4945,2462,7374,2809,5668,7832,4630,2417,5612,7824,8140,4674,7690,11632,8684,11774,1682,5507,7809,11649,10442,8514,6483,9704,6653,2706,10920,1560,3734,2289,327,7069,4521,4157,4105,2342,10868,12086,12260,3507,501,10605,1515,1972,7304,2799,3911,7581,1083,7177,6292,4410,630,90,3524,2259,7345,6316,6169,6148,6145,4389,627,10623,12051,12255,8773,6520,2687,3895,2312,5597,11333,1619,5498,2541,363,3563,509,7095,11547,12183,3496,2255,9100,1300,7208,8052,6417,7939,9912,1416,5469,6048,864,1879,2024,9067,6562,2693,7407,9836,10183,8477,1211,173,7047,8029,1147,3675,525,75,7033,8027,8169,1167,7189,1027,7169,9802,6667,2708,3898,4068,9359,1337,191,5294,6023,2616,7396,11590,8678,8262,6447,921,10665,12057,3478,4008,11106,12120,3487,9276,10103,6710,11492,8664,8260,1180,10702,5040,720,3614,5783,9604,1372,196,28,4,10534,5016,11250,10385,12017,8739,3004,9207,6582,6207,7909,4641,663,7117,8039,2904,3926,4072,7604,6353,11441,3390,5751,11355,10400,8508,2971,2180,2067,5562,11328,6885,11517,6912,2743,3903,11091,3340,9255,10100,4954,7730,6371,9688,1384,7220,2787,9176,4822,4200,600,7108,2771,3907,9336,8356,8216,8196,4682,4180,9375,6606,7966,1138,10696,1528,5485,11317,8639,10012,6697,7979,4651,2420,7368,11586,10433,3246,7486,2825,10937,3318,474,7090,4524,5913,7867,4635,9440,11882,3453,5760,4334,9397,3098,10976,1568,224,32,10538,3261,3977,9346,10113,8467,11743,12211,3500,500,1827,261,5304,7780,2867,10943,6830,7998,11676,1668,5505,2542,9141,4817,9466,6619,11479,5151,4247,7629,4601,5924,6113,6140,9655,6646,2705,2142,306,7066,2765,395,1812,3770,11072,8604,10007,11963,1709,9022,4800,7708,9879,6678,954,5403,4283,4123,589,8862,1266,3692,2283,9104,11834,12224,7013,4513,7667,6362,4420,2387,341,7071,9788,6665,9730,1390,10732,10311,1473,1966,3792,7564,11614,10437,1491,213,1786,9033,3046,9213,10094,1442,206,1785,255,1792,256,10570,1510,7238,1034,7170,6291,7921,11665,3422,4000,2327,2088,5565,795,10647,1521,5484,2539,7385,1055,7173,8047,11683,1669,1994,3796,5809,4341,9398,11876,12230,10525,12037,12253,3506,4012,9351,4847,2448,7372,9831,3160,2207,5582,2553,7387,6322,9681,1383,10731,1533,219,5298,4268,7632,6357,9686,8406,4712,9451,10128,4958,5975,11387,8649,11769,6948,11526,12180,1740,10782,6807,2728,7412,4570,4164,4106,11120,12122,8754,11784,3439,5758,11356,6889,9762,11928,1704,1999,10819,12079,12259,7018,11536,1648,1991,2040,2047,2048,10826,12080,8748,8272,8204,1172,1923,7297,2798,7422,6327,4415,7653,6360,11442,12168,7005,8023,9924,8440,8228,2931,7441,1063,3663,5790,9605,10150,1450,8985,11817,10466,10273,12001,3470,7518,1074,1909,7295,9820,4914,702,5367,7789,8135,9940,1420,3714,11064,12114,12264,1752,5517,9566,11900,1700,3754,5803,829,1874,7290,2797,10933,5073,7747,8129,6428,6185,11417,1631,233,5300,9535,10140,11982,8734,8270,2937,10953,8587,8249,2934,9197,4825,5956,4362,9401,1343,3703,529,10609,12049,6988,6265,895,3639,4031,4087,4095,585,10617,8539,4731,4187,9376,3095,9220,10095,10220,1460,10742,12068,1724,5513,11321,6884,2739,5658,6075,4379,11159,10372,8504,4726,9453,3106,7466,11600,10435,8513,9994,8450,9985,3182,10988,8592,2983,9204,4826,2445,5616,6069,867,3635,5786,11360,5134,2489,10889,12089,1727,7269,2794,9177,1311,5454,9557,6632,2703,9164,10087,1441,3717,531,3587,2268,324,5313,759,1864,5533,2546,7386,9833,8427,4715,11207,1601,7251,4547,11183,12131,1733,10781,10318,1474,10744,5046,4232,11138,10369,6748,964,7160,4534,7670,8118,8182,4680,11202,6867,981,8918,1274,182,26,7026,8026,11680,12202,10521,1503,7237,4545,5916,9623,8397,11733,10454,3249,9242,6587,941,1890,270,10572,6777,9746,6659,6218,6155,6146,878,1881,7291,11575,12187,1741,7271,8061,11685,6936,4502,9421,4857,4205,7623,1089,10689,1527,8996,10063,11971,10488,6765,2722,3900,9335,11867,6962,11528,5158,4248,4118,5855,2592,5637,6072,2623,7397,8079,9932,4930,5971,853,3633,519,8852,11798,3441,11025,1575,225,8810,11792,12218,3501,9278,3081,9218,4828,7712,8124,11694,12204,3499,4011,573,3593,5780,7848,9899,10192,1456,208,7052,2763,7417,11593,10434,12024,8740,11782,10461,3250,5731,7841,9898,1414,202,3540,7528,2831,2160,10842,5060,4234,4116,588,84,};
int32_t omegas_montgomery[PARAM_N/2]={4091,7888,11060,11208,6960,4342,6275,9759,1591,6399,9477,5266,586,5825,7538,9710,1134,6407,1711,965,7099,7674,3743,6442,10414,8100,1885,1688,1364,10329,10164,9180,12210,6240,997,117,4783,4407,1549,7072,2829,6458,4431,8877,7144,2564,5664,4042,12189,432,10751,1237,7610,1534,3983,7863,2181,6308,8720,6570,4843,1690,14,3872,5569,9368,12163,2019,7543,2315,4673,7340,1553,1156,8401,11389,1020,2967,10772,7045,3316,11236,5285,11578,10637,10086,9493,6180,9277,6130,3323,883,10469,489,1502,2851,11061,9729,2742,12241,4970,10481,10078,1195,730,1762,3854,2030,5892,10922,9020,5274,9179,3604,3782,10206,3180,3467,4668,2446,7613,9386,834,7703,6836,3403,5351,12276,3580,1739,10820,9787,10209,4070,12250,8525,10401,2749,7338,10574,6040,943,9330,1477,6865,9668,3585,6633,12145,4063,3684,7680,8188,6902,3533,9807,6090,727,10099,7003,6945,1949,9731,10559,6057,378,7871,8763,8901,9229,8846,4551,9589,11664,7630,8821,5680,4956,6251,8388,10156,8723,2341,3159,1467,5460,8553,7783,2649,2320,9036,6188,737,3698,4699,5753,9046,3687,16,914,5186,10531,4552,1964,3509,8436,7516,5381,10733,3281,7037,1060,2895,7156,8887,5357,6409,8197,2962,6375,5064,6634,5625,278,932,10229,8927,7642,351,9298,237,5858,7692,3146,12126,7586,2053,11285,3802,5204,4602,1748,11300,340,3711,4614,300,10993,5070,10049,11616,12247,7421,10707,5746,5654,3835,5553,1224,8476,9237,3845,250,11209,4225,6326,9680,12254,4136,2778,692,8808,6410,6718,10105,10418,3759,7356,11361,8433,6437,3652,6342,8978,5391,2272,6476,7416,8418,10824,11986,5733,876,7030,2167,2436,3442,9217,8206,4858,5964,2746,7178,1434,7389,8879,10661,11457,4220,1432,10832,4328,8557,1867,9454,2416,3816,9076,686,5393,2523,4339,6115,619,937,2834,7775,3279,2363,7488,6112,5056,824,10204,11690,1113,2727,9848,896,2028,5075,2654,10464,7884,12169,5434,3070,6400,9132,11672,12153,4520,1273,9739,11468,9937,10039,9720,2262,9399,11192,315,4511,1158,6061,6751,11865,357,7367,4550,983,8534,8352,10126,7530,9253,4367,5221,3999,8777,3161,6990,4130,11652,3374,11477,1753,292,8681,2806,10378,12188,5800,11811,3181,1988,1024,9340,2477,10928,4582,6750,3619,5503,5233,2463,8470,7650,7964,6395,1071,1272,3474,11045,3291,11344,8502,9478,9837,1253,1857,6233,4720,11561,6034,9817,3339,1797,2879,6242,5200,2114,7962,9353,11363,5475,6084,9601,4108,7323,10438,9471,1271,408,6911,3079,360,8276,11535,9156,9049,11539,850,8617,784,7919,8334,12170,1846,10213,12184,7827,11903,5600,9779,1012,721,2784,6676,6552,5348,4424,6816,8405,9959,5150,2356,5552,5267,1333,8801,9661,7308,5788,4910,909,11613,4395,8238,6686,4302,3044,2285,12249,1963,9216,4296,11918,695,4371,9793,4884,2411,10230,2650,841,3890,10231,7248,8505,11196,6688};
int32_t omegas_inv_montgomery[PARAM_N/2]= {4091,4401,1081,1229,2530,6014,7947,5329,2579,4751,6464,11703,7023,2812,5890,10698,3109,2125,1960,10925,10601,10404,4189,1875,5847,8546,4615,5190,11324,10578,5882,11155,8417,12275,10599,7446,5719,3569,5981,10108,4426,8306,10755,4679,11052,1538,11857,100,8247,6625,9725,5145,3412,7858,5831,9460,5217,10740,7882,7506,12172,11292,6049,79,13,6938,8886,5453,4586,11455,2903,4676,9843,7621,8822,9109,2083,8507,8685,3110,7015,3269,1367,6397,10259,8435,10527,11559,11094,2211,1808,7319,48,9547,2560,1228,9438,10787,11800,1820,11406,8966,6159,3012,6109,2796,2203,1652,711,7004,1053,8973,5244,1517,9322,11269,900,3888,11133,10736,4949,7616,9974,4746,10270,126,2921,6720,6635,6543,1582,4868,42,673,2240,7219,1296,11989,7675,8578,11949,989,10541,7687,7085,8487,1004,10236,4703,163,9143,4597,6431,12052,2991,11938,4647,3362,2060,11357,12011,6664,5655,7225,5914,9327,4092,5880,6932,3402,5133,9394,11229,5252,9008,1556,6908,4773,3853,8780,10325,7737,1758,7103,11375,12273,8602,3243,6536,7590,8591,11552,6101,3253,9969,9640,4506,3736,6829,10822,9130,9948,3566,2133,3901,6038,7333,6609,3468,4659,625,2700,7738,3443,3060,3388,3526,4418,11911,6232,1730,2558,10340,5344,5286,2190,11562,6199,2482,8756,5387,4101,4609,8605,8226,144,5656,8704,2621,5424,10812,2959,11346,6249,1715,4951,9540,1888,3764,39,8219,2080,2502,1469,10550,8709,5601,1093,3784,5041,2058,8399,11448,9639,2059,9878,7405,2496,7918,11594,371,7993,3073,10326,40,10004,9245,7987,5603,4051,7894,676,11380,7379,6501,4981,2628,3488,10956,7022,6737,9933,7139,2330,3884,5473,7865,6941,5737,5613,9505,11568,11277,2510,6689,386,4462,105,2076,10443,119,3955,4370,11505,3672,11439,750,3240,3133,754,4013,11929,9210,5378,11881,11018,2818,1851,4966,8181,2688,6205,6814,926,2936,4327,10175,7089,6047,9410,10492,8950,2472,6255,728,7569,6056,10432,11036,2452,2811,3787,945,8998,1244,8815,11017,11218,5894,4325,4639,3819,9826,7056,6786,8670,5539,7707,1361,9812,2949,11265,10301,9108,478,6489,101,1911,9483,3608,11997,10536,812,8915,637,8159,5299,9128,3512,8290,7068,7922,3036,4759,2163,3937,3755,11306,7739,4922,11932,424,5538,6228,11131,7778,11974,1097,2890,10027,2569,2250,2352,821,2550,11016,7769,136,617,3157,5889,9219,6855,120,4405,1825,9635,7214,10261,11393,2441,9562,11176,599,2085,11465,7233,6177,4801,9926,9010,4514,9455,11352,11670,6174,7950,9766,6896,11603,3213,8473,9873,2835,10422,3732,7961,1457,10857,8069,832,1628,3410,4900,10855,5111,9543,6325,7431,4083,3072,8847,9853,10122,5259,11413,6556,303,1465,3871,4873,5813,10017,6898,3311,5947,8637,5852,3856,928,4933,8530,1871,2184,5571,5879,3481,11597,9511,8153,35,2609,5963,8064,1080,12039,8444,3052,3813,11065,6736,8454};
