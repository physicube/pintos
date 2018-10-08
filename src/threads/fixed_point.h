#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define P 17
#define Q 14
#define FR 1<<(Q)

#define ADD_F_I(x, n) (x) + (n) * (FR)
#define SUB_F_I(x, n) (x) - (n) * (FR)
#define INT_TO_FP(x) (x) * (FR)
#define ROUND_TO_INT_ZERO(x) (x) / (FR)
#define ROUND_TO_INT_NEAR(x) ((x) >= 0 ? ((x) + (FR) / 2) / (FR) : ((x) - (FR) / 2) / (FR))
#define F_F_MUL(x, y) ((int64_t)(x)) * (y) / (FR)
#define F_F_DIV(x, y) ((int64_t)(x)) * (FR) / (y)


#endif
