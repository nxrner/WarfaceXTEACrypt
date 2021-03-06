#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>

//Warface g_xml_tea_key
#define CRY_TEA_KEY new unsigned int [4] { 0x4DD87487, 0x0C15011B0, 0x5EDD6B3D, 0x43CF5892 }

// src and trg can be the same pointer (in place encryption)
// len must be in bytes and must be multiple of 8 byts (64bits).
// key is 128bit:  int key[4] = {n1,n2,n3,n4};
// void encipher(unsigned int *const v,unsigned int *const w,const unsigned int *const k )
#define TEA_ENCODE( src,trg,len,key ) {\
	register unsigned int *v = (src), *w = (trg), *k = (key), nlen = (len) >> 3; \
	register unsigned int delta=0x9E3779B9,a=k[0],b=k[1],c=k[2],d=k[3]; \
	while (nlen--) {\
	register unsigned int y=v[0],z=v[1],n=32,sum=0; \
	while(n-->0) { sum += delta; y += (z << 4)+a ^ z+sum ^ (z >> 5)+b; z += (y << 4)+c ^ y+sum ^ (y >> 5)+d; } \
	w[0]=y; w[1]=z; v+=2,w+=2; }}

// src and trg can be the same pointer (in place decryption)
// len must be in bytes and must be multiple of 8 byts (64bits).
// key is 128bit: int key[4] = {n1,n2,n3,n4};
// void decipher(unsigned int *const v,unsigned int *const w,const unsigned int *const k)
#define TEA_DECODE( src,trg,len,key ) {\
	register unsigned int *v = (src), *w = (trg), *k = (key), nlen = (len) >> 3; \
	register unsigned int delta=0x9E3779B9,a=k[0],b=k[1],c=k[2],d=k[3]; \
	while (nlen--) { \
	register unsigned int y=v[0],z=v[1],sum=0xC6EF3720,n=32; \
	while(n-->0) { z -= (y << 4)+c ^ y+sum ^ (y >> 5)+d; y -= (z << 4)+a ^ z+sum ^ (z >> 5)+b; sum -= delta; } \
	w[0]=y; w[1]=z; v+=2,w+=2; }}

struct read_file_result_t {
	unsigned char* data;
	uint64_t size;
};
read_file_result_t read_file(const char* filename) {
	read_file_result_t result = {};
	FILE* f = fopen(filename, "rb");
	if (f) {
		fseek(f, 0L, SEEK_END);
		size_t size = ftell(f);
		fseek(f, 0L, SEEK_SET);
		unsigned char* data = (unsigned char*)malloc(size);
		if (data && fread(data, 1, size, f) == size) {
			result.data = data;
			result.data[size] = 0;
			result.size = size;
		}
		else {
			fprintf(stderr, "Error reading file %s\n", filename);
		}
		fclose(f);
	}
	else {
		fprintf(stderr, "Error opening file %s\n", filename);
	}
	return result;
}

bool write_file(const char* filename, const unsigned char* data, size_t size) {
	bool result = true;
	FILE* f = fopen(filename, "wb");
	if (f) {
		if (fwrite(data, 1, size, f) != size) {
			fprintf(stderr, "Error writing file %s\n", filename);
			result = false;
		}
		fclose(f);
	}
	else {
		fprintf(stderr, "Error opening file %s\n", filename);
	}
	return result;
}

int main(int argc, char** argv) {
	if (argc < 2) {
		printf("Usage: CryTeaDecrypt.exe <input filename>\n");
		return 1;
	}
	char* filename = argv[1];

	read_file_result_t f = read_file(filename);

	char* fileBackup = new char[MAX_PATH];
	strcpy(fileBackup, filename);
	strcat(fileBackup, ".bak");

	write_file(fileBackup, f.data, f.size);

	if (*f.data == 94 && f.data[1] == 36 && f.data[2] == 120)
	{
		int size = f.size - 3;
		char* res = new char[size];

		memcpy(res, f.data + 3, size);
		res[f.size] = 0;

		for (int i = 0; i < f.size; i++)
			res[i] = ~res[i];

		TEA_DECODE((unsigned int*)res, (unsigned int*)res, size, CRY_TEA_KEY);

		write_file(filename, (unsigned char*)res, size);
		//debug
		//printf("%s\n", res);
	}
	else {
		TEA_ENCODE((unsigned int*)f.data, (unsigned int*)f.data, f.size, CRY_TEA_KEY);

		for (int i = 0; i < f.size; i++)
			f.data[i] = ~f.data[i];

		int size = f.size + 3;
		char* res = new char[size];

		res[0] = 94;
		res[1] = 36;
		res[2] = 120;
		res[size] = 0;
		memcpy(res + 3, f.data, f.size);

		write_file(filename, (unsigned char*)res, size);
		//debug
		//printf("%s\n", res);
	}

	return 0;
}