import sys
import falcon

#Initalise 512-degree polynomials:
f_512 = [6, -5, -2, 4, 7, 4, 4, 6, -6, 8, 0, -5, -2, -6, 10, 7, 4, 3, 2, 1, 0, 0, 1, -1, -4, 2, -3, -2, 4, -2, 1, -4, 3, -2, -3, 3, 6, 6, 2, 0, 0, 6, -1, 2, 3, 2, 2, 1, -1, -1, -3, -3, -7, 4, 2, -1, -2, -4, 1, 0, 5, -7, 3, -4, 2, -5, -5, 1, 0, -3, 0, -2, 1, -7, 4, 1, 1, -3, 3, 3, -2, 6, 0, -8, 3, 5, -8, -3, 2, 5, -7, -8, 5, 1, 4, 0, 5, 2, -5, 10, 4, 1, 7, 0, -4, 4, 7, -3, 3, 3, 4, 8, -2, 8, -9, -4, 2, 2, 4, 0, 2, -3, -4, -10, 3, -10, 6, 7, -2, -7, -5, 3, -1, 4, 2, -3, 2, -3, 2, -2, -3, 3, -3, 4, 0, 3, -2, -1, 1, 9, 4, -4, -5, 2, 1, -5, -4, -4, -4, -2, 4, -6, 1, -5, -5, 2, -2, -11, 0, 2, -4, -3, 0, 3, 0, -8, -1, 0, -1, -6, -4, 1, -3, 2, -3, 0, -5, 7, 1, 5, 8, 6, 1, -7, 4, 1, 0, -1, -3, 0, -1, -8, 0, 2, 7, 3, 5, -3, 3, -1, -3, -2, -1, 6, 3, -8, 0, 5, -7, -4, 1, 1, 1, 2, 4, -1, 8, 0, -4, 3, -3, -3, 1, -1, 2, -2, -1, -2, 8, -2, -2, -2, 2, -6, 2, 6, 2, 3, -1, -10, 2, 4, 2, -2, -3, -5, 1, 1, 1, -6, 0, 2, 0, -3, 1, -1, 3, 0, -1, 1, -5, -4, -2, 1, 7, 3, -8, -3, -3, -1, 6, -3, 0, 7, 0, -7, 4, -4, -2, -2, -2, -4, 0, 6, 4, 2, -7, -6, 1, 0, -4, 1, -4, 3, -2, -3, 6, -1, -4, 7, -1, -5, 1, 3, -3, -1, 6, 4, 1, 6, -5, -3, -2, 0, -1, -3, -2, 12, 8, -2, 0, 0, -1, 4, 1, -3, 3, 5, 12, 0, -7, 1, -1, 3, 2, 5, -1, 2, 1, -9, -3, 3, -1, 0, 5, -2, -2, 3, 3, -2, 1, 2, 2, 3, -4, -1, -1, 1, -2, 3, 2, 0, -3, 4, 2, 5, 1, 1, -2, 0, 6, -1, 1, 5, 1, 0, -4, -3, 1, 7, -3, 0, -4, -3, -4, 1, -4, 0, -6, 2, -3, -2, 2, -4, 1, -1, 3, -1, -3, 7, -2, -5, -11, 5, -2, 1, -4, -4, 0, -1, -4, -3, 4, 3, -3, -1, 4, -4, -7, -2, -1, 0, 6, -6, 2, -3, -7, -4, 7, 2, 6, -7, -2, 3, -3, 9, -7, 10, -7, -1, 2, -1, 1, -3, 2, 2, 1, 3, 3, 3, 2, 4, 2, 2, -2, 5, -2, -7, 7, -1, 1, 4, 0, 1, -6, 6, -12, 2, -13, 0, 1, -6, 2, -9, -5, 8, 2, 0, -2, 4, -1, -3, -3, 1, 4, -2, 0, -5, 2, -4, -1, -2, -1, -4, 1, 2, 2, 1, 3, 2, 0, -2]

g_512 = [-4, 0, 5, 4, -6, 6, 2, 1, -2, 3, 1, 0, 8, 2, -3, -2, -5, 5, 4, 2, -7, 1, 0, 1, -1, 1, -2, -1, 7, 2, 4, 0, 8, -5, -4, 6, 3, 2, 9, -1, 0, -8, -2, -7, -7, 2, -1, -9, -1, 5, -2, -1, 3, -4, -2, -1, 3, -7, -7, -2, -1, -3, -6, -1, 6, -3, -8, 2, -3, -8, 1, -4, 1, -3, 3, -1, 3, -3, -4, 0, 7, -3, 1, 4, 4, 5, -9, 2, -1, -2, -6, 2, -4, -1, -3, 2, -2, -4, -5, 9, -6, -3, -3, -5, -1, 0, 2, -5, 0, 10, 0, -2, -8, 2, 3, 0, 2, -8, -1, 3, 2, 0, -6, 0, 1, 4, 1, -1, -4, 1, -4, -1, 1, 1, -3, -4, -1, -4, 5, 1, 2, 0, 3, -2, 7, 4, -1, 1, -4, 2, 1, 4, -1, 1, 7, -4, 1, 1, -2, 6, 5, -3, 1, -6, -1, 11, 1, -4, 0, -1, -4, 6, -3, 2, -5, -8, 0, 3, 1, 0, -5, -3, -2, 3, 3, -5, -8, -4, 1, 7, -5, 5, -1, 5, 3, 1, -5, 3, -7, -2, 1, -2, 2, -5, 0, -2, -8, -9, 1, 0, -7, 3, 7, 0, -3, 1, -1, 2, 0, -4, -3, 3, -1, -2, 3, -5, -4, 3, 1, -3, -2, 0, 3, -2, -6, 2, 0, -5, 6, -1, 1, 1, 0, 2, 0, -2, 0, 5, 5, 1, 5, 6, 8, -5, -2, -3, -4, -6, 4, -6, -4, -3, -1, 3, 8, -4, 4, -1, 6, 1, -1, -4, 1, 0, 3, -3, 1, -5, 3, 3, -1, 1, 0, 4, -3, -2, 1, 1, -2, 10, 8, 4, 1, 3, 0, 2, -6, -1, 2, 2, -4, 1, 3, 0, 7, -2, -6, 4, -9, -3, 3, 2, -1, 3, 0, 1, -5, 0, 0, 8, 0, -7, -1, 6, -3, 1, -1, 0, 8, 2, 1, -1, 2, -5, 7, 5, 6, -9, -3, -2, 4, -3, 0, 9, -3, -2, -3, 3, -1, 2, -1, 3, 1, 3, 2, -5, -5, 0, 7, -7, -1, -4, 1, 2, -4, 0, -2, -6, 6, -3, -7, 2, -2, 5, -4, -1, -2, -4, 1, -3, 1, 1, 0, 6, -3, -1, 2, -3, 4, -5, 0, 0, 2, -2, -2, -3, 1, 1, -2, -4, -1, 0, 4, 7, -4, 1, -9, 1, 7, 3, -8, -7, -1, -6, -4, -4, 1, 3, 3, 0, 8, 1, -3, 2, -1, -8, 6, -4, -1, 3, 2, -1, 0, 2, -2, 7, 5, -1, -12, 4, 1, -1, -7, 3, -10, 3, 2, -1, -3, 6, 3, -1, -4, -1, 0, -2, 0, -3, -4, 2, -2, 3, 1, -2, 2, -4, -6, 12, -1, 2, -3, 1, -1, -5, 10, 2, -6, 2, 1, -4, -5, -3, -7, -2, -4, 0, -5, -3, -3, -3, -2, -4, 3, 0, 2, 4, 7, -1, -3, -2, 3, 6, 5, -6, 0, -5, -3, -5, 3, 2, 6, 6]

F_512 = [-21, 1, -55, -26, 2, -1, -50, -22, 42, -29, -17, -4, 33, -48, 44, -19, 42, 11, -12, -18, 1, -15, -26, 10, 18, -14, 15, -21, -11, 30, 2, -19, -22, 40, -23, -46, -21, 23, 0, 22, -6, -24, 3, 16, -18, -2, 2, 15, 31, -20, 27, -16, -16, -12, 9, -5, 61, -4, 42, -31, -20, 1, 0, -2, -3, 26, 28, 25, 45, -7, 9, 26, 23, 49, -7, -14, 39, 2, -5, 13, 26, -18, -18, -2, 31, -2, 38, 33, 50, 7, -42, 10, -7, 32, 10, -24, -27, -24, -21, -10, -4, 1, 22, 3, -28, -5, 5, -24, -22, -22, 57, -16, 5, -43, 21, -3, -13, 6, 3, 8, 17, -10, 10, -2, -21, -18, 21, 5, 32, 23, -56, -47, 22, 2, -42, 2, 7, -20, -45, 26, -40, -4, -9, -20, -1, -21, -45, 2, 13, 11, 67, 30, -22, -13, -22, 35, 25, 25, 40, -6, -68, -28, 47, 49, -18, -21, 5, 0, -4, -44, -31, 27, 52, -13, 3, -51, 36, 14, 16, -19, 35, -6, -15, 37, -29, 6, 3, -18, -20, 26, 8, -7, 70, 20, -5, -17, -7, 60, -1, 2, 2, 23, -37, -15, -2, -5, 51, -48, 1, -52, 28, 0, 59, 16, -3, -4, -73, -6, 57, 3, -1, 45, 9, -41, 0, 13, -4, -6, -15, -30, 2, 16, 1, 11, 14, 36, 3, -27, 24, -22, 1, -3, 30, 31, -5, -13, 40, -30, -51, -6, 21, -24, -37, -24, 1, -24, -22, 6, 6, -56, -3, 30, -6, 28, -20, 33, 4, 15, 62, -4, -14, -39, 5, 11, 18, -27, 2, -3, -3, -27, -49, 2, 22, 5, 7, -31, -9, 38, 10, -48, -24, 0, 31, -4, -15, 23, -33, -27, 55, -7, -37, -11, 1, 15, -35, 23, 12, 12, -10, -7, -18, 41, -2, 13, -12, -40, 6, 9, 4, -36, -23, 79, -55, 1, -23, 11, 26, -20, -10, 2, 9, -37, -9, 2, -28, 34, -1, 62, -35, 12, 9, -19, 5, 22, 2, -8, 19, 3, 24, 13, -28, 10, 2, -10, -3, 34, 27, -31, 20, 23, -22, -57, -26, 12, 38, -12, -20, 6, -11, 5, 17, -42, 4, -13, 32, 5, -32, 23, 28, -21, 37, 22, -18, 51, 9, 18, -18, 16, -3, -25, 25, 4, 12, 14, -11, -85, -34, 6, 9, 17, -30, -9, -11, -8, -19, 6, -11, 11, 47, -14, -16, 25, 17, 61, -22, 17, -8, 44, 21, 7, 29, -22, 35, 7, 3, 18, -59, 18, -1, -9, -9, 6, 6, -40, 10, -20, 41, -30, 15, -10, -34, -5, -18, -12, 0, 13, 2, 1, -11, -14, 28, 31, 11, -35, 7, 0, -44, -2, -64, -11, -28, 2, -3, 34, -33, 3, -21, -40, 12, 24, 16, 2, -23, -29, -5, -4, -7, 12, -32, 35, 33, -63, -11, 23, 59, -67, 13, 25, -20, -6, -96, 12, 3, 51, -47, 25, -29, -23, -14, -13, 17, 0, -25, 39, 0, -27, -22, -6, -8, -3, 52, 1]

G_512 = [61, 13, -14, 12, -1, 5, 9, -16, -31, -31, -1, 47, 13, 5, 32, -11, -4, 59, -10, 42, 38, 11, 8, 63, 50, 12, -20, -9, -15, -46, 23, 27, -5, 34, -1, 28, -12, -25, 19, 30, -22, -33, 22, 19, 30, -42, -35, 9, 17, -3, 4, 35, -54, 26, 14, -25, -23, -34, 24, 38, -11, -28, 4, 2, 31, 5, -25, -46, 39, 7, -21, 16, -32, -42, -4, -18, 6, 20, -17, -19, -29, -72, 41, -8, 17, -17, 14, -18, 12, -26, -26, -12, 38, 30, -31, -62, -54, 23, -9, 17, -26, -26, 21, 2, -11, -14, 25, -35, -5, 27, -19, -6, -37, 8, -16, 9, 14, 18, 5, -19, 19, -14, 16, -38, 9, 10, 5, 13, 26, -9, 31, 14, 22, 26, -35, 6, 26, 23, -47, 39, -15, -3, -65, 25, -5, -28, 19, -4, -25, -27, -5, 8, -47, 7, -8, -16, 17, 30, 7, 29, -6, 2, 38, 39, 27, -69, 26, 6, 25, 38, 16, 58, 6, 17, -29, 14, -27, 31, 36, -23, -28, -15, -58, 21, -13, -43, 18, 13, 16, 6, 18, 0, 28, -5, 5, 27, 58, -16, 22, -24, -16, 12, 32, -1, 5, -48, 5, 31, -22, -8, -18, -39, -1, 45, -35, -20, 4, -1, 11, -14, -52, -9, 24, 16, 23, -4, -30, -30, 31, -23, -61, 13, -8, -17, -21, -28, -25, 16, -8, -6, 1, 27, 48, -17, -24, -18, -14, -15, -64, 10, 1, -25, 25, -38, -35, -35, 30, 33, 11, -25, -46, -38, 14, 16, -58, 12, 27, -45, 17, 22, 46, -36, 31, 34, -21, -3, 16, 25, 35, -35, -5, 31, 32, 2, 3, -12, -6, -10, -16, -11, -5, 19, -21, 7, -46, 22, 0, 82, -14, -50, 4, 50, 46, 49, -59, 2, 28, -33, 1, 47, -4, 39, 39, 45, 54, 6, 4, -30, -21, -2, -6, 7, -68, 8, -29, -32, -22, 26, 10, 45, 23, 11, 15, 10, -26, 22, -10, -10, 2, -11, -9, 32, 9, 15, -3, -15, 11, 5, 19, -30, 3, -14, 49, -53, 8, 17, 26, 40, -49, 1, 27, -2, -21, -40, -22, -3, -46, -32, -24, -40, -34, -34, 10, -19, -8, -13, 67, -12, 3, 3, 49, -19, 12, 2, -17, -22, -20, 14, -10, 1, -19, -2, -34, -27, -4, 18, -58, 20, 19, 34, -24, 21, -12, -10, -30, 2, -20, 8, 16, -17, 9, -26, 19, -40, 34, -1, 4, -34, -13, 8, -14, 11, 37, 13, -2, 18, -22, 13, -14, 0, -13, -27, 24, -3, 12, 5, 16, -14, 22, 20, 8, 32, 17, -4, -39, -8, -20, 30, 62, 23, 9, 37, 4, 5, 32, -19, 0, 32, 5, 0, -22, 2, -8, 19, -32, 43, -11, -29, 34, 0, 6, 9, 29, -53, -9, 17, 10, -11, -16, 13, 9, 20, 2, 26, -18, -11, 32, 30, -71, -30, 1, 1, 7, 32, -31, 9, -6, -28, 1, -4, 15, 7, -36, -30, 10, -26, -18, -22, -33, -6, 24, -40]

polys_512 = [f_512, g_512, F_512, G_512]

#Initalise 1024-degree polynomials:
f_1024 = [-1, 3, 1, -3, 2, 4, -5, 7, 2, -1, -4, 1, 0, -5, 4, -8, -2, 4, 2, 5, 1, 1, 5, 1, -5, -1, 3, 4, -1, 0, -3, -3, 1, -1, 2, -7, -2, 5, -5, -3, 2, 0, 0, 2, -1, 2, 0, 1, -4, 1, -5, 3, -4, 0, 6, -3, -4, -4, -3, 1, -5, -2, -2, 4, -1, 1, 1, -2, 0, -3, -2, -1, 2, 1, -3, -3, -2, 0, 3, 0, 3, 2, 0, 1, 0, 0, 0, -3, -2, 2, -3, 0, 1, 0, 1, 1, 4, 2, 1, -4, 1, 2, -3, 2, -1, 6, -4, 1, 5, -4, 0, -2, 2, -1, -4, 2, 0, -3, 1, -3, -1, 2, 1, 2, -4, -1, -2, 2, 6, -5, -3, 3, 1, 0, -2, -1, 1, 0, -2, 7, 2, 1, 2, -1, 3, 2, 2, 1, -2, -1, 0, 5, -5, 1, 1, 3, 1, 3, 1, 1, 0, 2, 2, 0, -2, -1, -1, 1, 5, -1, -5, 0, 0, -2, -3, 0, -3, 4, 3, 0, -4, -3, 1, 4, 0, 1, 0, 1, 2, -5, -3, 1, 1, -3, 2, -2, -4, 3, -2, -4, 6, 4, 4, 0, -4, 1, 2, 4, 1, 5, 1, -2, 1, -2, 0, 0, 4, -4, 0, -3, -3, 5, 0, -1, 1, 3, 3, -4, 0, -1, -3, -1, 2, 0, -1, -1, 0, -2, -1, 1, 4, -4, -2, 0, 0, 5, 1, -1, 6, 2, 1, 4, 0, 3, -2, 0, -1, 2, 1, -3, 2, -1, 4, 3, 0, 0, -4, 1, 0, 3, 1, -4, 4, -4, -2, -4, -2, 0, -3, 6, 2, -3, 1, -3, 4, -4, 0, 0, -1, -6, -2, 0, 2, -1, 3, -4, -1, -1, -1, -4, 0, 4, 1, 0, -2, 1, -3, 2, -3, -1, 0, 2, 2, -3, 2, -1, -1, 2, 3, 5, 3, -3, -1, -1, -7, 5, -3, 0, -4, -4, 0, 3, 1, -3, 0, 3, -1, -5, 2, 2, 2, 4, 0, 2, 2, -7, 4, 4, 4, -3, 2, -3, -1, 0, -1, 4, -3, 3, 0, 3, -2, 0, 1, 0, 3, -1, -5, 4, 1, -1, -3, 3, 2, -1, -1, 2, -1, -5, -1, -1, 0, -4, 0, 2, -5, -1, -2, 5, 1, 1, 1, -1, 1, 2, -3, 1, 4, -2, -2, 3, -5, 4, 0, -6, 1, -3, 1, 1, 0, 3, 3, 5, -3, -2, -3, 0, -4, -5, -2, 0, -3, -1, -5, -1, -4, -4, 3, 3, 7, 0, 0, -6, 1, 0, 4, 3, 0, 1, 0, -5, 2, -1, 1, -3, 2, -1, -1, -4, 2, 3, -1, 2, -1, 0, 5, 2, 2, 1, 0, -1, 4, -4, -2, 1, -1, 3, 4, 2, -5, 1, 0, 2, 0, 0, -6, 0, -2, 0, 2, 0, -2, 2, 2, -4, -1, 0, 0, 0, 2, 0, 0, 0, 4, -1, -3, -2, -3, 1, -1, 0, -5, 1, 1, 2, 0, -3, 1, -3, 0, 3, 0, 3, 1, -4, 2, -1, 1, 4, 0, 1, -1, -2, -2, 3, 0, -1, 3, -3, 1, -2, -1, -2, 3, 3, 5, -1, 2, 2, -1, -1, -3, -3, 1, 2, 0, 0, -2, 2, -4, -5, 0, 5, -4, 3, -4, 0, 3, -3, 3, -1, -4, -4, 0, 5, 0, -3, -4, 4, -4, 0, -1, 2, -2, 5, -3, 0, 1, -3, -2, -2, -2, 4, 3, -1, -5, -2, 2, -3, -1, -1, 2, -5, -2, 7, 1, -1, -2, -5, 4, -2, -2, 2, 1, 2, 7, -1, 6, -2, -3, 1, 1, 1, -1, -1, 0, -1, 1, 1, 1, 2, 0, 0, -4, -5, -3, 2, 5, 1, 6, -3, -1, -4, 4, -3, -1, 5, -3, 1, -1, -3, 2, -3, -2, 4, 2, 4, 7, -1, 6, 5, 1, 3, 2, 4, -6, 2, 4, -2, 0, 0, 6, 0, -1, 10, 5, -4, 1, 0, 2, -2, -1, -2, 2, -2, 0, -2, -3, -4, -5, -1, 3, 3, 3, -3, 2, 5, 0, 2, 3, -1, -4, 3, -5, 0, 2, 2, 0, -2, 1, 3, 1, -1, -6, 6, -3, 0, -4, 2, 1, -1, 6, 2, -6, -1, 1, 4, -4, -3, -4, 1, 0, 0, 5, 0, 0, -1, -3, 5, 4, -5, -5, 3, 3, 0, 5, 2, -2, -6, 0, 3, -1, -2, -1, 3, -1, 1, 6, -5, -1, 0, -1, -1, -4, -1, 1, -1, 5, 1, -5, -1, 1, 3, -6, 3, 2, 1, -5, 1, 1, -2, 2, -5, -5, 2, 0, 0, -5, -4, 3, -4, -3, 6, -7, 0, 0, -1, 2, 1, 4, 2, -4, 4, 4, -1, -3, 3, 0, -2, -3, 1, 4, -2, 0, 1, 2, -2, 0, 0, -2, 1, -5, -1, -2, 3, -5, 2, -1, 3, -2, 0, 3, -2, 5, 5, 1, 2, 0, 3, -2, 4, 2, -1, 1, 0, 1, 1, -1, -3, -3, -1, -5, 6, -2, 1, -3, 5, -2, 1, 0, 1, 2, 0, -5, -4, -1, -1, -1, -2, -2, 1, 1, -4, -1, 1, -2, -2, -2, -2, 1, 0, 3, -3, 6, 1, 0, -3, -1, -1, 0, -1, 2, 4, -2, 0, 2, -2, 0, -4, 2, -2, -2, 5, -7, -2, 1, -2, 0, 2, -4, -1, 2, 2, 5, 1, 0, 3, 6, 0, 3, -1, 1, -1, 3, 1, 4, 0, -4, -6, -2, 3, -1, 2, 2, 4, -1, 5, 0, 5, 2, 6, 4, 1, -3, -5, 4, 0, -4, 5, 2, 0, -3, 3, 2, -2, 1, 0, 1, 4, 0, -1, 3, 2, -2, 1, -7, -1, -3, -4, -3, -3, 0, 0, 5, 0, -1, 0, -4, 3, 2, 2, 2, 0, 0, 0, 4, 6, 4, 1, 3, 4, -1, 3, 0, -2, 2, -6, 4, -2, 3, -1, -1, -1, -3, 0, 3, 3, 1, -2, -4, -1, 3, 1, 0, -5, 0, 0, 2, -5, 4, 0, 1, 2, 3, -1, -2, -1, 0, -1, 1, -2, 3, 1, -1, -3]

g_1024 = [0, -4, 0, -1, -1, 0, 0, 4, -2, -3, 1, 4, -1, 1, 2, -1, 1, -7, 0, -3, -4, -3, 1, -2, -4, 6, 2, -1, -2, -5, 4, 0, -3, -1, -1, 1, 5, -1, -3, -2, -1, -1, -1, 6, -2, 1, 3, 5, -1, 2, -2, 3, -4, -4, 1, -1, -3, 0, -2, -4, -1, -3, 2, -3, 0, 2, 0, -6, 0, -2, -3, -4, 7, -1, -1, -2, 2, -4, -3, 1, -5, -2, 1, 2, -7, -4, 2, -4, 1, -4, 0, 1, -2, -3, 2, -2, -4, -3, -5, 0, -2, 5, 1, 0, -2, -5, 1, 3, 1, 1, 1, 2, -3, 6, 2, 4, -1, 3, 0, 2, 0, -2, 0, -2, -2, 0, -1, -2, 1, -4, 0, -2, -3, -1, 2, 6, 0, 0, -3, 1, 4, 2, -1, 2, 0, 6, -9, 2, -3, 3, -2, -5, 2, -2, 0, 3, -1, 0, -2, 2, -3, -8, -4, 4, 1, 2, -4, -4, 2, 2, -1, 0, 4, -2, -2, 1, 2, 3, -3, 2, 1, 2, 7, 0, -2, 1, 1, -1, -1, 2, 0, -1, -3, -5, -1, 7, -1, 4, 6, -2, -1, -2, -4, 5, 2, 1, 1, -4, 1, -2, 2, -3, -2, -2, 2, 3, -1, 2, -1, 6, 4, -2, -3, -4, 1, 1, 0, -1, -4, 0, 0, 0, -3, 0, 2, 1, -7, -2, -1, -4, -3, -2, 1, -1, 5, 3, 5, -4, 4, 0, -1, 1, -1, -2, -1, -5, -1, 2, 4, -1, -5, 2, 2, -3, 2, -1, -1, 3, 8, -2, 0, 1, -3, -4, 3, 1, -4, 3, -1, 2, -2, -2, 2, -2, 0, 0, 2, 1, 5, -4, 1, -2, 1, 4, 4, 2, 3, 1, 4, -3, -1, 1, 1, 7, 3, 4, -5, 0, 0, -6, 3, -1, 0, 4, 7, -2, 0, 3, 0, 2, 0, 3, 1, -2, 0, 0, -2, 1, -3, -1, 3, 4, -4, -2, -1, -4, 1, 2, 3, 2, -5, 2, 2, 1, 1, -3, -2, -3, -3, 3, 1, -2, 3, -5, -2, -3, 3, 2, -3, 0, -4, 1, 1, 2, 1, 1, -2, -5, -3, 1, -1, 2, -3, 0, 3, 0, -2, -4, -1, -5, 1, -1, 4, -2, 0, 0, 1, 1, 3, -6, 1, -1, -1, -4, 3, 1, 1, 3, 1, 1, 2, -2, -1, 3, -3, -3, -4, -3, -1, 2, -2, 2, -2, 2, -1, 1, -1, -3, 2, -5, 5, 7, 3, -1, 0, 0, -1, 1, 2, -1, -2, 3, -4, -1, -3, 3, 2, -3, -2, -6, 4, 0, 1, 7, 3, -3, 1, -2, -3, -3, 2, -2, 2, -2, 0, -1, 3, 3, 2, -4, -2, 5, 3, -2, 2, -2, -3, -1, 3, 3, 0, -1, -3, 1, 1, -4, -4, 6, 2, 1, 1, -2, -2, -2, 3, 0, 2, 2, 0, 3, 0, 1, -1, -2, 2, 1, -5, 4, 5, -3, -3, -2, 0, -1, 0, 7, -1, 2, -1, -3, -2, -2, -3, 0, 0, 6, -2, -1, -3, -1, -2, 4, 3, -1, -1, 4, 2, 1, -3, -1, 1, 1, -1, 0, -5, -1, 1, 6, 0, 0, 1, -1, 4, -5, 1, 0, -3, 2, 3, 1, 2, 1, 0, 5, 4, -3, 0, -4, -2, -2, -3, 3, 5, -3, 2, -5, 2, -1, 3, 0, -1, -3, -2, -1, 0, -3, -2, -3, -5, -3, 0, -1, -1, -3, 1, -2, -2, 4, 4, -3, 3, 1, -1, 2, 0, -3, 2, 1, 1, -1, 6, -4, -7, 0, 0, 1, 0, 0, 3, 4, -3, -2, -3, -2, 0, 2, 6, 3, 1, 0, -3, 0, 0, -3, 0, 3, 3, 1, 5, 2, 1, -2, -2, -1, -3, -2, -2, -1, 2, -7, 2, -1, -3, 2, 1, 5, 4, 0, -1, -1, 1, -5, -4, 2, -2, 3, -3, -1, 3, 0, 3, 1, -6, 0, -5, 3, -4, -2, -3, 1, -2, -1, 0, -2, 4, 1, 6, 1, 6, -2, -1, 1, -2, 0, 0, 3, 1, 1, -1, -3, 3, 5, 0, 3, -3, 2, -2, -2, 3, 0, -1, 3, 7, 1, 3, 1, -2, 1, 2, 3, 1, -2, 1, -4, 3, 5, -2, 2, 1, 5, 2, 2, 4, 1, 0, 2, -1, 0, -4, 4, 0, 1, 2, -3, -5, -4, -3, -3, 3, -9, -5, 4, 0, 7, -2, 0, -3, 2, 0, -2, 4, 4, -7, 1, 0, -2, 0, -1, -5, -1, 4, -4, 4, 5, 0, 4, -2, -2, 0, 0, 1, -3, -6, -1, -1, -5, 2, 0, 0, 1, 0, 2, -7, 1, -1, 3, 2, -6, -1, -5, 3, -1, 1, -4, -3, -8, 2, 1, 5, -1, -2, 0, 2, -6, 0, 3, -1, -3, 6, 0, 2, 3, -2, -4, -1, -2, -3, -3, -1, -1, 1, 1, -3, 4, -5, 4, 2, 0, 5, -1, -1, 1, 4, 2, 1, 2, -4, 1, -6, 2, 2, -3, -2, -4, 2, 2, 2, 2, 3, 1, -1, 0, -4, -4, -1, -3, 4, 1, 5, 2, 1, -1, 0, 2, 0, 0, -2, 5, -2, 0, -4, 2, -2, 0, -4, -3, -2, 2, 0, 0, 1, -1, 1, -3, 0, 1, -6, 4, 5, 2, -2, 3, -1, -3, 3, -1, 6, 6, 1, 1, 2, 2, -2, 3, 2, 1, -4, 0, -1, 2, 1, 0, -3, -1, -1, -3, -5, -3, 1, 2, -3, 1, 1, 3, -2, -4, 0, 0, 0, 4, -2, 0, 4, -3, 1, 2, -2, -2, 1, 0, 1, -5, 1, 1, 0, 4, -1, -3, 1, 7, 1, -4, 1, -3, 1, 4, 0, 4, -2, -7, -1, -2, -3, -2, 2, 1, 4, 1, -6, -3, 3, 0, -2, 0, 0, 0, 4, -2, -1, 1, 4, 1, 4, 1, 3, -2, 3, -2, -1, 2, 2, 4, -2, 3, -1, 2, -2, -2, 1, 1, 3, 0, 4, -6, 1, 3, 3, 1, -4, 3, 4, -1, 3, -1, -2, -3, -1, 0, 2, -1, -4, -3, -1, 0]

F_1024 = [-6, 25, 23, -14, -32, 4, 21, -31, 16, -25, 12, 5, 17, 16, -69, 77, -49, -1, 7, 3, 19, -31, -1, -41, 64, 22, -16, -55, 44, 51, 14, -6, 23, 22, -5, -32, 11, 22, -11, -63, -26, 2, -17, 16, -23, -2, -23, -15, 16, -9, -20, 5, 40, -9, 10, -10, 5, -32, -22, 8, 60, 22, 18, 7, -18, -17, -34, -5, -46, 14, 35, 23, 20, 26, -30, 34, 15, 6, 23, 8, 32, 22, -53, 12, -27, 26, 11, 20, 2, -5, 6, -1, 21, -18, -38, -14, -46, 10, 3, -52, -25, 19, 1, 0, -41, 2, 65, -5, 0, -38, -23, 52, 6, -4, 33, -8, 11, 14, 14, 5, 15, -11, -43, 10, -33, 36, -11, 17, -26, -17, 54, -32, -22, 3, 17, -23, -35, 29, 46, -24, -6, -52, 23, -37, -60, 48, -2, 19, 8, -41, -1, 6, 39, -1, 16, -58, 17, -33, -33, 25, 17, 5, 29, -47, 1, 20, 28, 7, 20, -46, 38, -3, 54, -16, -29, -12, -19, 58, -19, -11, 4, -40, 4, -8, -23, 13, -2, 5, -14, 13, -2, -3, 48, -53, -6, 23, 38, 42, -13, 73, -8, 31, -58, 5, -13, 1, -1, 37, 16, 16, -11, -6, 2, 42, -39, 22, -21, 26, -21, -7, -23, 14, -9, -13, 36, -16, -35, 26, -43, -16, -17, 41, 26, 12, -50, 35, -8, -43, 2, -9, -16, 22, -38, -5, -24, -9, -28, 12, -14, 5, -20, -24, 43, -29, -43, 9, 9, -11, -29, -7, -17, -8, -24, 31, 21, -21, -15, 44, -4, -10, -17, -25, 13, 17, -7, -2, -17, 11, 4, -35, -24, 48, -20, -4, -41, -7, 26, 15, -6, -20, -34, 30, -29, -57, 35, 23, -20, 32, -35, -20, 24, -10, 36, 7, -12, 36, 24, 9, 6, 81, -9, -10, 33, 7, 37, -25, -12, 36, 14, -5, 12, -19, 67, 31, -18, 22, 50, 10, 30, -17, 0, 26, -14, 1, 1, -37, 12, 8, -12, 18, -16, -12, 2, -13, 14, -32, -61, 4, 6, 28, -23, -37, 8, 29, -35, -41, 29, 38, 5, -10, -64, 27, -37, -26, 33, 6, 3, -10, -12, -26, 13, -32, -18, 27, -38, -22, -28, -20, -6, 24, 32, -3, 2, -40, 45, 22, 12, 41, -1, 37, -9, 39, 2, -62, -11, -22, 13, -27, 5, -39, -35, -17, 14, 37, 33, -9, 1, -33, 39, -6, -29, -15, 26, -36, -19, -28, -22, 2, 10, 37, 1, 20, -14, -43, -36, -40, 35, 21, -25, 24, -28, 31, -3, -7, -3, -6, 14, 5, -6, -10, -43, 13, -34, 47, 64, -14, 30, -28, -25, -15, 33, 20, -8, -16, 18, 23, -19, -25, -17, -36, -1, -2, -21, 3, 3, 24, 69, -40, -9, -11, -23, 49, 38, 31, 20, 2, 3, -35, 10, 0, 5, 9, 21, -19, 53, -32, -43, 20, -23, 22, 8, 21, 0, 6, 15, -29, 30, -1, 16, -3, 19, -8, -4, 28, -15, -24, 32, -15, 31, 36, -25, -15, -22, -20, 58, -24, -8, -55, -37, 39, -50, 41, 4, 22, 10, -12, 49, -24, 22, -13, 16, 0, -29, -1, -15, -41, -3, 12, 4, -6, 6, -3, 30, 2, -4, -7, -2, 22, -22, -18, -8, 25, 3, 9, 19, -25, 40, -30, -4, -15, -8, 50, 12, -36, 35, 9, 44, -12, 10, -25, -36, -13, -16, -11, -24, 28, -5, -11, -36, 38, 43, 12, 41, -2, 69, -35, -11, -19, 36, 20, 11, -10, -11, -5, -78, -25, 26, -20, 20, 17, 22, 31, -27, 44, -8, 36, -25, -14, 66, -41, 11, 25, 0, 19, -25, 31, 2, -24, -13, -4, -16, -8, -20, -2, 35, 7, 8, 15, -42, 57, 25, 20, 2, 25, -58, -22, 1, 40, -34, -40, -1, 9, -7, 6, 8, 11, 4, 13, -6, -52, -3, 41, 15, -31, 10, -15, -55, 29, 62, -11, 8, -20, -24, -20, 14, -21, -27, -30, -31, 41, 8, 7, -13, -22, 12, 36, -3, -7, -8, -21, 6, -32, 6, 8, -37, -23, 15, 20, -62, 14, -3, -11, 7, 58, 31, -50, -4, 32, 17, -1, -20, 45, 10, 6, 37, 40, 18, 14, 23, -29, 7, 7, -21, 27, -11, -35, -2, 10, -2, 1, -23, 22, 47, 14, -27, -3, -22, -24, 22, -17, -2, 10, 28, 21, -11, -24, -8, 16, -18, 7, -12, -15, 28, -50, 21, -6, -10, 11, -38, -26, 25, -13, -25, 50, 9, -27, 28, 3, -28, 27, -21, -40, 17, -1, -31, 19, -10, 15, -15, -43, -18, -31, 27, -39, 17, 44, -30, -10, -25, 15, -13, 2, -11, -17, 36, -18, -26, 24, 2, -16, -41, 36, 21, -39, -18, -34, -4, 17, 21, 2, 50, -31, 18, 15, 31, 17, -24, 35, 2, -61, 6, 8, -5, 4, -16, 66, -12, -2, 4, 10, 8, 11, 28, -28, 18, -71, -36, -28, -2, -25, 5, 8, -19, 25, -22, 7, -64, 5, -7, 43, 24, -14, 8, -34, 0, -4, 7, 26, -42, 24, -12, -3, 29, -15, 3, -17, 15, 45, -5, -41, -20, 13, 10, -37, -30, 26, -16, 0, 21, -14, -4, -16, -17, -12, 27, -27, -26, 19, -31, 4, 46, 33, -25, -60, 10, -16, -11, -102, 21, 25, 16, -15, 31, 40, 39, -32, -46, 12, 43, 15, 25, -4, -7, -4, -6, -5, -22, -12, -7, 20, 3, 5, -19, 47, 6, -37, 2, 17, -6, -5, -12, 12, -11, 6, 43, 23, 12, -6, -9, -23, 0, 31, -13, -45, -13, -25, -2, -14, -21, 5, 6, 12, 23, -45, 0, 39, 0, -18, 6, 0, -18, 0, 26, 28, 7, -39, 46, -31, 11, 30, 3, -9, 1, -7, -69, -14, -24, 22, 25, -18, 18, -25, 7, 15, 32, 12, -19, 58, -2, -4, -31, 36, 2, -41, 15, 32, 26, -4, 4, 3, 25, 44, 2, 1, 16, 8, 3, -3, 15, 42, 14, -4, 4, 51, -15, 32, -12, -24, -46, 8, 12, -18, 23, -14, 9, 2, -20, 27, -1, 40, -16, -24, 8, -6]

G_1024 = [19, 20, -16, -23, -8, 27, 64, 3, 15, 5, 6, 9, -16, -3, -4, -2, -30, 13, -6, 15, -30, 35, 8, 11, -22, -23, -30, -8, -37, -12, -42, 15, -3, -12, 2, 5, -23, 12, -14, 16, 16, 18, 33, -36, -42, -13, -35, -14, 3, -28, -23, 14, -2, -19, 5, 30, -8, 44, -7, -47, 11, 40, -21, -48, 8, -42, 22, -31, 2, 10, 14, 44, -24, 41, -39, -15, -35, -7, -43, -2, -13, -17, 17, -7, 28, -17, -8, 45, 31, 6, 10, -4, 23, -1, 17, 22, 37, -15, 34, -9, 13, 17, 50, 11, 43, 6, -21, -6, 25, -24, -18, 29, -1, 6, 22, 29, -15, 0, 6, -4, 4, -25, 4, 11, 23, 26, -2, -31, -9, -14, -2, -5, 42, 29, -3, 7, -34, -5, 3, -27, 14, -40, -51, 7, -33, 24, 6, -18, 10, -41, 1, 7, -37, -52, 22, -33, 4, 12, 8, 58, -2, -9, -3, -2, 0, 55, 44, -15, -18, -16, -54, -41, 1, -20, 11, 8, -5, -18, 34, 5, 2, 4, 43, -5, 0, 18, 0, 28, 0, 2, 13, -15, -13, -13, 33, 35, -7, -6, -91, -9, -59, 31, -21, -25, -7, -23, -6, 54, 47, -45, -21, -17, 39, -31, -2, 15, -33, 11, 35, -4, -42, -4, -17, -14, 43, -7, -26, 33, -6, 39, -36, -44, -30, -28, 19, -37, 66, 11, 16, -9, 5, 63, 27, 18, -23, -13, -24, 2, -39, 14, 31, -13, -4, -8, 17, 3, -33, -24, -45, 15, 7, -22, -3, 0, -4, 34, -4, -3, 60, 40, -10, -11, 37, 8, 2, -8, -26, 13, 8, -28, -13, 0, 2, -15, -14, 23, -7, 17, 23, 23, -3, -24, -48, 21, 29, -14, -3, -16, -16, 1, -10, -4, 0, -46, 32, -5, -4, -17, 0, -36, -15, 25, 57, 9, 23, 19, -47, -20, -19, -20, -45, -5, 23, 33, 4, -39, -4, -52, -27, -17, 0, -31, 15, -15, -8, 7, -6, -20, 19, 19, -10, -7, 15, -49, -33, 8, -4, 13, 36, 0, -10, 31, -11, -4, -21, 17, -38, 1, 48, 20, 5, 24, 7, -4, -18, -40, 22, -3, 29, -16, -12, 61, 2, -27, -29, -12, 6, -15, -26, 31, -41, 33, -33, 32, 51, -33, 15, -17, -9, 10, -22, -8, -18, 0, 0, -8, -53, -12, -4, 40, -16, -4, -32, 22, 5, 13, 0, 22, 20, -7, -26, -13, -25, 22, -24, -8, -30, 1, 3, -50, -22, -5, -25, -29, 15, -20, -33, 0, -21, -47, -57, 5, -19, -42, 25, -39, 9, -3, 18, 33, -6, 14, -15, -21, 1, -5, -5, -18, 1, -53, 22, -67, -10, 45, 33, -3, -18, -35, -34, 20, 17, 2, 4, -16, -13, 16, 39, 27, 20, 23, 6, 4, -31, 1, 59, -9, -22, -64, -23, -30, -28, 28, 46, 44, 13, 36, 3, -2, 27, -10, 26, 17, 1, 9, -1, -26, -22, -1, 5, -10, 19, 23, 53, -38, -24, -11, 6, -41, 60, 33, 3, -29, -4, 1, 14, -2, 43, -21, 31, -36, -21, -13, 12, 21, -1, -16, 25, 9, 13, -5, -14, -4, -25, -5, -1, -21, 43, 35, -7, -33, -36, -10, 6, 41, 23, 7, 26, 23, -15, -37, -30, 25, -3, -40, 13, -1, 21, -55, -13, 17, 7, 63, -19, 24, -46, 5, -2, -29, 11, 1, 21, 11, -9, -5, -52, -13, -2, 16, 31, -4, 16, 29, -59, 15, 20, -9, -9, -33, -5, 13, -18, 35, -6, 18, 32, 12, 6, -6, 17, -10, -51, 16, -13, -10, 11, 11, 56, 37, 73, -6, -37, -12, 6, -49, -3, -3, 21, 2, -42, -8, -4, -25, -17, -35, -4, 23, 40, 48, -21, -12, -43, -24, -15, 5, 16, -10, -14, 14, 34, 37, 6, -16, 54, 40, -8, -6, -9, -8, 19, -11, -24, -14, -5, 38, -11, 46, 0, 1, 23, 6, 44, -8, 61, -42, 40, -33, 9, 42, 23, 27, 8, -16, -6, -9, 36, -6, 18, -19, 12, -21, 32, -11, -17, -17, 18, 19, -32, 40, 1, -2, 29, -24, -18, 19, 47, 0, -49, -4, -2, 9, 7, -35, 65, -13, -24, -25, 17, 9, -52, 21, 8, -3, 0, -40, -30, 23, 42, -10, 10, -4, -19, 4, 8, -48, -18, 20, 31, -36, 31, 35, -51, 1, -41, -13, -1, -42, 3, -2, -12, 39, -17, 43, -17, -24, -3, -10, 4, -1, 31, 18, -4, 17, -42, -26, 15, -43, 2, 27, -7, -15, 7, 18, 3, 37, 35, 56, 16, 20, -12, -5, -2, 36, -37, 48, 5, 40, 2, -19, -17, -2, -1, 21, 38, -2, -17, 25, 17, 24, -30, -8, -19, -13, -49, -6, 13, 31, 24, -33, 24, 11, 11, 6, -44, 13, 1, -13, -63, -13, 0, 58, 26, 19, -28, -26, 1, 16, 29, -2, 10, -5, -25, -15, -63, -15, -2, -1, 9, 54, 19, -2, -36, -21, 35, -33, 6, -38, -15, -13, -9, 3, 3, -37, -16, 17, 52, -19, -48, 20, -28, -3, 30, 16, 17, -43, 19, 8, 0, 34, -2, -10, -3, -46, -6, -11, -16, 5, 14, 14, 20, -14, 9, -24, -2, 1, 41, 39, -52, -23, -9, 6, 11, -22, -35, -23, 42, 24, 9, -2, 4, -15, -27, -57, 7, 1, 49, -18, 7, 6, -30, 34, -19, -17, 10, 28, 19, 67, -67, -16, -3, -15, -2, -31, -21, -9, 2, 9, 22, 13, 7, -26, 29, 5, 40, -9, -28, -77, 0, -14, 15, -34, 21, -28, -14, 25, -13, -23, 36, -2, -9, -13, -10, -1, -21, 26, -29, 18, -34, -4, 27, 22, 35, -11, -26, 9, 21, -19, 19, 1, -49, -10, 19, 19, -39, -33, 34, 31, 29, 22, -44, -22, -53, 39, -27, -1, 23, 28, -11, -7, 9, -29, -24, 12, -19, 24, -25, 37, -33, -10, 1, -44, -16, 13, 4, -13, -6, 45, -18, 27, 17, -13, 11, 17, -49, -17, -23, -15, 14, 10, -25, 31, 31, -23, 10, -3, 2, -51, 26, 1, 3, 7, -14, 31, 31, 49]

polys_1024 = [f_1024, g_1024, F_1024, G_1024]

sk_512 = falcon.SecretKey(512, polys_512)
sk_1024 = falcon.SecretKey(1024, polys_1024)

if len(sys.argv) < 3:
    sys.exit('Insufficient arguments')

if sys.argv[1] == '512':
    sk = sk_512
    print('========== n = 512 ==========')
elif sys.argv[1] == '1024':
    sk = sk_1024
    print('========== n = 1024 ==========')
else:
    sys.exit('Enter either 512 or 1024 as 2nd command line argument')

if sys.argv[2] == 'o':
    ind_sym = 'o'
    sk.sign(b'hi')
elif sys.argv[2] == 's':
    '''
    Test SMK for varying n \in [8, 1024] for 1000 iterations
    '''
    print("================== Testing SMK ==================")
    for n in [8, 16, 32, 64, 128, 256, 512, 1024]:
        print('========== n =', n, '==========')
        sk = falcon.SecretKey(n)
        sk.sign(b'hi', 's', sigma_og=60, sigma_new=30)
elif sys.argv[2] == 'i':
    '''
    Test IMHK for sigma_og \in [50, 165] => slightly above 165 is the original sigma used in FALCON
    '''
    print("================== Testing IMHK ==================")
    for sigma in range(50, 166):
        sk.sign(b'hi', 'i', sigma_og=sigma, overwrite=True)

else:
    sys.exit('Enter o/s/i 3rd command line argument (original/symmetric/independent)')
