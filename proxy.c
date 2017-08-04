/*
 * proxy.c - Web proxy for COMPSCI 512
 *
 */
#pragma GCC diagnostic ignored "-Wunused-variable"


#include <stdio.h>
#include "csapp.h"
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#define   FILTER_FILE   "proxy.filter"
#define   LOG_FILE      "proxy.log"
#define   DEBUG_FILE    "proxy.debug"

#define MAX_CONNECTION_ATTEMPTS 5

/* [liuzhuan] key values */
const unsigned char g_pbRootPrvKey[] = { "\
\x30\x82\x04\xA5\x02\x01\x00\x02\x82\x01\x01\x00\xD1\x3E\x8C\x9D\
\xDE\x6D\x96\x3F\x47\x1C\x49\xC9\x91\x71\xFB\xC4\x5C\x62\xDF\xFF\
\x89\xE8\x9F\x74\x15\x58\xF7\xF4\xF9\x5F\x6A\xAB\x90\x85\x74\x8F\
\xEA\x2F\xAC\xB9\x6B\x1C\x09\xCF\x52\xF0\x82\x2C\xD0\x32\xD0\x34\
\x6F\x12\x4C\xB2\xC9\x08\xBC\xED\x36\x94\x21\xD5\x4C\x0C\x38\xEF\
\x5D\x2B\x97\xBA\x00\xD5\xBF\xA4\xB2\xFC\x7C\xCD\x73\xD9\x72\x85\
\x33\xCF\xA3\x38\x1A\xF0\x20\xE5\x44\xE3\xAB\xDA\x90\xB0\xD8\x04\
\xE3\x89\xAB\x62\xD4\x20\x84\x65\x37\x05\x4C\xEA\x3A\x11\x8E\x6E\
\x46\x62\x1F\xD9\xE5\x24\xED\x06\xE4\xBA\x15\x26\x25\xAE\xE1\xBB\
\xA2\x03\x90\x1C\xDE\x7B\x22\xDC\x87\xB1\xC3\x98\xD8\x7B\xAA\x71\
\xFD\x8E\x2F\xBE\x23\xA2\x86\xCF\x16\x30\xDC\xFD\x20\x16\xCF\x85\
\xFC\x49\xF2\x35\x75\x10\xB9\x11\xB3\x36\x66\x21\xBB\x15\x32\x85\
\x18\x14\xC4\x6C\x13\xFA\x7C\xA2\x6A\x72\x18\x41\xBC\xEB\x9B\x2C\
\xB3\xA9\x20\xEA\x98\x09\x29\x03\x7A\xCE\xFE\xB7\xC8\xA8\xAC\xCB\
\x31\xAA\xE1\x58\x2B\x62\x04\xF8\xA6\x90\x7E\xF5\x19\xD9\x38\x05\
\x31\xEB\x6B\xAB\xE9\x7B\x2A\x3F\x7E\x6F\x74\xEE\x4C\x2F\x34\xF9\
\x1C\x75\x71\x2B\x91\xEF\xE3\xAB\x00\x78\x9B\xEB\x02\x03\x01\x00\
\x01\x02\x82\x01\x01\x00\x85\x5D\x73\xAC\xAF\x77\x73\x9B\x13\x4C\
\xE1\x6E\xDB\x08\x26\x6B\x2A\x63\x4E\xD8\x05\xE3\x41\xB6\x70\x60\
\xCB\x71\xD5\x7B\xCE\x76\x59\x5F\xE6\x42\x50\x06\x60\xF5\xB1\x62\
\x26\x92\x81\x0F\x90\x38\xD5\xDE\x7D\x3B\xDE\x4B\x70\x9D\x47\x6B\
\x0D\x57\xB8\x40\xC4\x2B\xBA\x13\xD4\x3A\x24\x4D\x43\xA0\xA7\x25\
\x95\xC7\x78\xD9\x5B\x06\x6C\x3F\x7D\x31\x8F\x2B\x59\xA1\xC9\xF1\
\xA1\x55\xE0\x09\xA8\xA0\x5F\x36\x88\x08\xDD\xAA\x02\x95\xB4\x14\
\xA1\xAE\x0D\x5A\x90\x82\x7D\xCE\x70\xD4\xB2\x81\x9A\x41\x7C\x3E\
\x83\xE0\xAF\xEA\x36\xCD\x79\x8A\x04\x66\x6D\xA2\x3F\x3D\x46\x23\
\x76\x26\x2B\xBE\x16\xE4\xE6\x3C\x49\xD7\xFA\x4A\x50\x16\x6E\x15\
\xD5\x11\x13\xFD\xC2\xC1\x45\x29\x58\x01\xA2\x01\x67\xF4\x0F\x8B\
\x84\x50\xCB\x0E\xC5\xC2\xC3\x21\x26\x6C\xDC\x72\x29\xE6\x54\xEA\
\x8E\x1F\xCC\xF6\x2C\xFA\x97\x1C\xBF\xE9\x9E\x75\x77\xF7\xA7\x22\
\xAB\x5A\xC0\x2E\xDC\x44\x69\x1B\x2D\xEA\x05\x72\x1E\x60\x0C\x19\
\x92\xF2\x12\x01\x01\x68\xA2\xDE\x5C\x59\x2A\x44\xE1\x89\xF9\xE4\
\x76\xF6\xEF\x7A\x4D\xD2\x48\x49\xA6\x71\x37\x71\x47\x64\xDC\x11\
\x54\x65\x5D\xF7\xB1\x61\x02\x81\x81\x00\xEA\x82\x5E\xC9\x11\xBC\
\x4B\x9F\xF0\x8C\xFB\x35\xB6\xA8\x99\xC3\xDD\xED\x15\xF6\x08\x63\
\x74\xDB\xF7\xEC\xC1\x07\x4E\xF4\x08\x52\x7B\x80\xE9\x66\xFD\x5F\
\xFF\x09\x42\x5D\x28\x14\x41\x8A\x34\x95\x37\x4A\x87\x44\xDB\xC8\
\xFE\x50\xBC\x39\x44\x93\xC9\xDB\x09\xA5\x8B\xAC\x8E\xD5\x9B\xAA\
\x59\x0F\x7B\x82\xBB\xBD\xF7\xEE\x79\x7F\xFD\x23\xE9\x42\x1A\x06\
\x7D\xB2\x2B\xE3\xC5\xF7\xF3\x8D\x15\x84\xF3\x5A\x63\xEA\x58\x97\
\x6B\xF4\x0B\xC1\x3B\x14\x51\x2D\x9A\x11\xC4\x60\xF3\xBC\x52\x96\
\x35\xAF\x02\xA7\xFD\x7E\xAB\xCC\x6B\x51\x02\x81\x81\x00\xE4\x6B\
\x75\x94\x04\x42\x4F\x6B\x17\xBC\x47\x34\x45\xCD\xAE\x50\xAC\x2D\
\x2B\xB3\x73\xAA\xAB\x62\xBC\x90\xB7\xC2\x31\xD8\xB6\xEF\xB0\x57\
\xB9\x02\x19\x5D\x69\xFA\xD8\xDA\x11\x42\xC6\x73\xF5\x48\x55\x8E\
\xC2\x09\x85\x0A\xFF\x7C\x81\xF1\xF2\x99\x53\x08\x37\x86\xC5\xAC\
\x8F\x9B\x8A\xDA\x0F\xB1\xFB\x3D\x08\x80\x6A\xA3\xFD\xB4\xA3\xB7\
\x2B\xFF\x47\xFF\x11\xE5\xB5\x66\x69\x57\x76\x82\xC3\x44\x99\x34\
\x98\xD1\xB6\x40\xE8\xC9\x22\x4F\x32\xD0\x75\x2E\x81\x43\x58\x18\
\x32\xDD\xD8\x1B\x17\x88\xF7\xA6\x92\x5C\x0B\xD5\x4C\x7B\x02\x81\
\x80\x63\xD2\xB4\xF8\x50\x15\x5F\xF7\xA8\x14\xCB\x06\x35\x47\x95\
\x94\x9B\x8E\x45\x4F\xE2\x88\x3B\x81\x3B\x0A\xCB\xAC\x09\xBE\xB5\
\x20\x2F\x34\x53\xA6\x24\x6A\xCD\x8C\x2A\x74\xAF\x0F\xD8\x4A\x35\
\x51\xE3\x24\x55\x6A\x49\x48\x48\x81\x23\x6E\x19\x33\xF3\xB3\xCA\
\x6A\x6E\x87\x38\x91\xD2\xDE\x73\x64\xB4\xC5\x94\x97\x2B\xC7\x96\
\x6E\x95\xD9\xC8\x7B\xFB\xCA\x11\x8D\x5B\x43\x6C\xCC\xBC\x1E\xAD\
\x2F\x57\xCB\x7D\x46\x8F\x09\x7D\xC9\x77\x8B\x7C\x53\x8C\xAE\xA5\
\xAB\xB4\x75\x34\xAB\x50\x58\x62\x67\xA9\xF0\xCA\x66\x36\x49\x20\
\xD1\x02\x81\x81\x00\xB7\xBD\xB1\x51\x25\xB3\xE9\x8A\xAE\x07\x28\
\x07\xE6\x76\xB3\x57\xF5\x88\x48\x75\x0C\x00\x27\xE9\x3E\xE1\xF2\
\xCF\x65\xA5\x7C\x52\x86\xB9\xA9\xFB\x04\x48\x5E\x6E\x08\x6E\x32\
\x20\x52\xDF\x08\x59\xED\x68\xEE\xB1\x15\xB2\x69\x1D\xD0\xB1\xBD\
\x82\x94\x86\x31\x94\x5A\x02\x9B\x6A\x75\x61\x3F\xEA\xDD\xBC\x94\
\xD0\x27\xF8\x4E\xA7\x36\x62\xAC\x23\xA7\xD8\x88\x9F\x0D\x32\x9A\
\x5E\x5E\xD8\x85\x16\xF3\x5E\x99\xE7\x68\x02\x02\xBF\x78\xB7\xD8\
\x9A\x53\x08\xDB\xB6\x3E\x71\x08\xC9\xE7\x82\xB3\x85\xDC\x20\xC3\
\xEF\x03\x1D\xCB\x6D\x02\x81\x81\x00\xD6\x7E\xCA\x8C\x66\x19\x63\
\xDF\x84\x90\x49\x1A\x7F\xCB\x9C\xCA\x11\xBA\xA4\x37\x4E\xCE\x2F\
\x10\x6C\x25\xCD\xA4\x00\x59\xB2\x05\x25\xA6\x86\x24\x8D\x92\x56\
\xB9\x35\x68\x5C\x53\x36\x14\xB6\xCD\x96\x5D\x14\xA0\xB2\x02\xC7\
\x6C\x38\x83\x7E\xED\x09\x77\xB7\x11\x01\xAB\xDC\x59\x72\x23\xAE\
\x39\x58\xB9\xD3\x5B\x9C\x71\xB8\x5E\x8B\x87\x49\xE2\x7E\x88\xF9\
\x96\x1E\xDC\x60\x9B\xE7\xA0\xBD\x22\x5E\xD0\xEC\xFE\x02\xB9\xCE\
\x47\x26\x94\x73\x4D\x07\x69\xCD\xF6\x4D\xBD\xEA\x8C\x82\x4F\x64\
\x98\xF4\x7C\x1A\x7D\x90\x9A\x05\xD7" };

/* [liuzhuan] key values */
const unsigned char g_pbServerPriKey[] = { "\
\x30\x82\x04\xA3\x02\x01\x00\x02\x82\x01\x01\x00\xB5\xC3\x4D\xAD\
\xAF\x3D\x50\x12\x40\xE4\x6B\x03\x37\x86\xEA\xA6\xA7\x04\x69\xF0\
\xBE\x4B\xDC\x85\x89\x08\x2A\x74\xA8\x6A\x07\xCA\x91\x60\x6A\xF8\
\x20\x5D\x7D\xFF\xD7\x2C\xA6\xA4\x3F\x9F\x85\x46\x98\xC9\x0C\xE8\
\x8B\x95\xD0\x97\x79\x1F\x4C\xAC\x3F\x2E\x63\xB8\x34\x4C\xB6\x7F\
\xF0\x94\x82\x9D\xD2\x86\x9D\x47\x9A\x6C\x1B\x75\x14\x32\x90\x71\
\x81\x1F\xB2\x52\x26\x44\x14\x78\x57\x07\x4D\xE8\x23\x9B\xCA\x05\
\x47\xA3\x73\x5A\x44\xE4\xAB\x7A\xAD\xE8\x91\x1B\x78\x24\xB5\x07\
\xC8\xBE\xAD\xD1\xC4\x0A\xCF\x2C\x11\x3B\x57\x49\x93\xF6\x24\xE3\
\x51\xB9\x55\xA5\xD2\xC7\xC4\x2D\x6F\x0B\x4E\xC1\x20\x22\xFE\x67\
\xFA\x72\x3D\xCA\xD6\x00\xEF\xBC\xE6\x49\x7C\xF1\x01\xDC\x5C\x8F\
\xB6\x3A\x39\x53\xB6\x77\xFE\x15\x4E\x40\xE7\x6E\xAC\x2C\x40\x0F\
\xE3\xFA\x54\x41\x05\x91\xDA\x47\xC7\x7C\x20\xA0\xD6\x6D\x31\xE3\
\x58\xAA\x53\x0A\xB4\xAE\x8E\xCD\xD8\xA6\xA3\x78\x99\xA4\x91\x46\
\x12\xF4\x47\x04\x66\x9C\xE5\x47\x09\xB9\x45\xD3\xBD\xA2\x1F\x48\
\xB2\x9E\x36\xD7\xB0\x51\xA1\x54\x63\x81\xE0\xA1\x32\x01\xFC\x61\
\xBE\xAD\x47\xB6\x72\xF2\x6C\x05\x34\xAD\xEC\xBD\x02\x03\x01\x00\
\x01\x02\x82\x01\x00\x23\x16\xED\x2C\x16\xA4\x93\x8C\xB2\x92\x66\
\x46\x5C\xB5\xE3\x1F\x01\x27\x4C\xFC\x79\x00\x54\x36\x43\x5A\x1C\
\x38\x21\x3B\x36\xFD\xD8\x4A\xF0\xDB\xAE\x03\xDE\x8B\x41\x93\x11\
\x28\xAC\x4F\xB3\x7F\x09\x87\xE6\xC2\x0E\x10\x82\x10\x7C\x05\x9A\
\xDB\xB5\xE6\xD2\xC1\x80\xF7\x3E\x54\x3C\xB1\xAE\xF5\xA0\xEA\xF3\
\xFA\x1A\xC9\xBC\x13\x42\x2E\xF0\xCB\xB8\xCD\xD1\xB3\x22\x48\x0A\
\x5B\xA1\x11\x7B\xEC\xD0\xD3\x06\x91\x36\x5F\x4B\xA9\xA5\x9B\x2F\
\xAF\xA3\x5B\x3E\x88\x3B\x0D\x7B\x15\x61\x9F\xCE\x16\xAC\xEE\x19\
\x48\xBC\x9A\xE4\x22\xB0\xEF\xA8\x05\xF0\x21\x97\x7F\xA5\x23\x22\
\x08\x92\x9F\xCD\x0A\x1C\x0B\x90\x03\x32\xF5\x4D\x04\x52\x8B\xE7\
\x18\x90\xBD\xA0\x33\xD1\x14\x69\xEC\x44\xA0\x09\xD5\x08\x3D\xFA\
\x02\x1B\x70\x9D\xB1\x08\xD5\xB6\xFA\x3B\xD6\x4C\x0A\xDF\x7D\x97\
\x03\x0F\x44\x0C\x8E\x5A\x2B\xFD\xA7\x07\x7D\xF5\x2D\xEF\xDB\xFF\
\x13\x48\xB6\x39\x06\xAD\x6C\x71\x39\xC8\x83\x3F\xBD\x08\x66\x89\
\x47\xE1\x45\x77\x31\x95\x67\x70\x3C\xC1\x61\x6C\xED\x1E\xA9\x67\
\x71\x98\x18\x40\x05\xD1\xE7\x50\x28\xBE\x1D\x06\xEB\xE6\xB9\xC6\
\xC1\xA5\x2C\xD7\x51\x02\x81\x81\x00\xD9\x2C\xC5\x57\x16\xCF\x4D\
\x1D\xF9\x1A\x35\xE0\xE3\x26\xBE\x9D\x46\x29\x28\xB7\x8A\x45\x88\
\x03\xEF\x78\x1D\x0D\xAF\xD2\x82\x6C\xCA\x05\xB2\x17\xFD\xF3\x72\
\xC3\x06\xFD\x96\xD0\x34\x72\x01\x9F\x95\x03\x79\x04\xF6\xD5\x60\
\x76\x0A\xAF\xF1\x1F\xBA\x86\xAB\x35\xF8\x06\xE2\x0D\x94\xCE\xEB\
\xA3\xF0\xB6\xD0\xB8\x6A\xA5\x37\x94\x7F\x64\xE8\x3A\x89\x37\xB3\
\x4B\xF1\xE3\x8C\x8D\x99\xB4\xAA\xCD\x35\xF5\x1B\x5C\x02\x48\xFB\
\xAF\xB3\x78\x03\x19\xDF\x7B\x28\x1B\x8E\xA3\x32\x7E\xD6\x83\xAD\
\xE1\x67\xF0\x6E\x47\xD2\xF0\x3E\x2F\x02\x81\x81\x00\xD6\x41\xDE\
\x04\xA8\xD5\xA5\x1D\xCF\xBF\x60\xE6\x64\x63\x7A\x2A\xF3\xAD\xFF\
\x27\x45\xD5\xC9\x16\x78\x22\x29\xC3\x0B\x9A\xF9\xD6\xFD\x51\x39\
\x10\x12\x07\x30\xF9\x5F\xDB\x7B\x18\xF6\x24\x2E\x5F\xFE\xD2\xAA\
\x64\x77\x21\x11\xE0\x99\x6D\x26\x92\xD6\xFE\x1F\x55\x87\x05\xC2\
\x4C\x50\x19\x4E\x64\xF6\xC1\x9E\x35\xA5\x7F\x3D\xD2\x01\x18\x6F\
\x0C\xCC\x3E\xB7\x7D\x0B\xD7\x04\x18\xF8\x9C\x45\x17\x45\x87\xD5\
\x23\xC5\xFA\xC7\x72\x89\xB5\x50\xF4\x83\xFD\x2B\x01\x1B\x74\xC2\
\xEC\xBC\x2D\xB5\x2B\x72\xF9\xF2\xD3\x3C\x61\x14\xD3\x02\x81\x80\
\x1C\xFE\xDB\x42\x2B\x6B\x76\x12\x60\x65\xDD\x77\xAF\x1C\x47\x2A\
\xDC\x69\x36\x64\x7A\xF3\x99\x9B\x5C\xE7\x9E\x89\x6B\x46\x21\xDF\
\xC0\x81\x4E\x2B\xE1\xDE\x15\x1E\x70\xDA\x7E\xBE\x41\xA2\x4F\x11\
\x2D\x66\x0F\x4C\x58\x60\x58\xC6\xA9\xDA\x9F\xC8\xEA\xB0\x7C\x3F\
\x72\x64\x08\xDE\x63\x55\xD5\x24\x48\x49\x40\x48\xBF\x04\x5C\x0D\
\x59\x8C\xF1\x6C\x8F\x51\x7E\x80\xCF\x44\xE0\x49\x2F\x92\x6D\x93\
\x84\x76\xBB\x36\x67\x9F\xB2\xEA\xDC\x7D\x53\x7C\xAA\xD7\xD8\x9D\
\x05\x48\x48\xBF\xA2\x88\x66\x38\xC8\x15\xD3\xC3\x87\x28\x48\x45\
\x02\x81\x80\x28\x4C\xD5\x5C\xDD\x00\xEA\x80\xD3\xFD\xB4\x55\x41\
\x96\xB0\x78\xF9\xC2\xC5\x96\x76\x7D\x42\xC8\x96\x2A\x1E\xDE\xD0\
\x05\x03\x6F\x5B\xD0\x76\x42\x3E\x91\xD9\xB5\x5E\x41\x63\x43\x0B\
\xB1\x3C\x83\xD3\xE3\x7E\x27\x4D\x7D\x0B\xE6\xCA\x15\x0C\xC7\x5B\
\xE7\x0A\xAF\xC4\xA8\xE1\xA6\x06\xFE\xEB\x8E\xF4\x16\xF1\x12\x38\
\x21\xD9\xD7\xF1\x5A\xCE\x30\x83\x0E\x5C\xE7\x09\x5E\x15\x28\x39\
\x42\xF3\x7F\xF0\x15\x1F\x93\x0D\xFF\x20\x9A\xBB\xAA\x3E\x22\xEF\
\xDC\xA3\xC5\x1E\x8B\xF4\xCA\x20\x8F\x1C\x5F\xA2\xCD\xBE\xCD\xDA\
\xB2\x8B\xFF\x02\x81\x81\x00\xD3\x89\xC6\x20\xAF\x19\xC7\x8F\x04\
\x9D\x9D\x20\x95\xE0\x4F\xB0\x97\x19\x68\x85\x65\x7F\x9A\xF9\xF6\
\x91\x0D\xD1\xFB\x38\xEE\xFA\xA3\xD4\x02\x42\x2E\xBF\xEB\xEE\x13\
\x99\xEB\xD5\xE0\xE5\x66\xBC\x96\xFB\x63\x54\xFB\xFC\xCC\x8E\xFC\
\xCE\x95\xB0\x71\x1C\x6B\x4C\x77\x00\xBC\x96\x1A\x53\xE0\xF3\x61\
\x0B\x68\x93\x11\xFA\x76\xF4\xAF\x31\x49\x8D\x55\x86\xA3\x74\x8F\
\x59\xDB\xFA\xF9\xA0\x1C\x70\xB5\xB5\xE7\x78\xDA\x1C\xC8\xF5\x7B\
\x03\x2F\x1B\x48\x74\x2D\x79\xB2\x3B\x29\x15\xAE\x0F\x1A\x51\x28\
\x07\x53\x02\x7C\x9F\x24\xEC" };

/* [liuzhuan] 线程穿參 */
struct ppSSL
{
    int clientfd;
    int serverfd;
    SSL * ssl_client;
    SSL * ssl_server;
};

/* [liuzhuan] 测试server cert对应的私钥，可以一直使用此固定值，写在代码中 */
EVP_PKEY * createServerKey()
{
	EVP_PKEY * serverkey = EVP_PKEY_new();
	const unsigned char * p = g_pbServerPriKey;
	RSA * serverrsa = d2i_RSAPrivateKey(NULL, &p, sizeof(g_pbServerPriKey));
	if (NULL == serverrsa->n)
    {
		EVP_PKEY_free(serverkey);
	}
	EVP_PKEY_assign_RSA(serverkey, serverrsa);
	return serverkey;
}

/* [liuzhuan] 测试root cert对应的私钥，可以一直使用此固定值，写在代码中 */
EVP_PKEY * createRootKey()
{
	EVP_PKEY * rootkey = EVP_PKEY_new();
	const unsigned char * p = g_pbRootPrvKey;

	RSA * rootrsa = d2i_RSAPrivateKey(NULL, &p, sizeof(g_pbRootPrvKey));
	if (NULL == rootrsa->n) 
    {
		EVP_PKEY_free(rootkey);
	}
	EVP_PKEY_assign_RSA(rootkey, rootrsa);
	return rootkey;
}

/* [liuzhuan] Get Peer 签发证书, server_x509 真正的服务器证书（SSL链接时获取） */
X509 * createFakeCertificate(SSL * sslToServer, EVP_PKEY * serverkey, EVP_PKEY * rootkey)
{
    unsigned char buffer[128] = { 0 };
	int length = 0;

    /* [liuzhuan] ** watch this line, 这里拿到的是真正的对端服务器证书, 把这个证书作为自己的证书给浏览器,起一个劫持的作用 */
	X509 * server_x509 = SSL_get_peer_certificate(sslToServer);

	if (server_x509 == NULL) 
    {
        return NULL;
	}

	X509 * fake_x509 = NULL;
	int	nPos = 0;
	ASN1_INTEGER * a = NULL;
	X509_NAME * issuer = NULL;

	fake_x509 = X509_dup(server_x509);
	if (fake_x509 == NULL)
	{
		return NULL;
	}

	X509_set_version(fake_x509, X509_get_version(server_x509));

	a = X509_get_serialNumber(fake_x509);
	a->data[0] = a->data[0] + 1;

	issuer = X509_NAME_new();

	//根证书固定名称
	X509_NAME_add_entry_by_txt(issuer, "C", MBSTRING_ASC, (const unsigned char*)"CN", -1, -1, 0);
	X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, (const unsigned char*)"WTRoot", -1, -1, 0);
	X509_set_issuer_name(fake_x509, issuer);

	X509_set_pubkey(fake_x509, serverkey);
	//del
	nPos = X509_get_ext_by_NID(fake_x509, NID_info_access, -1);
	if (nPos != -1)
		X509_delete_ext(fake_x509, nPos);

	nPos = X509_get_ext_by_NID(fake_x509, NID_crl_distribution_points, -1);
	if (nPos != -1)
		X509_delete_ext(fake_x509, nPos);

	nPos = X509_get_ext_by_NID(fake_x509, NID_authority_key_identifier, -1);
	if (nPos != -1)
		X509_delete_ext(fake_x509, nPos);

	nPos = X509_get_ext_by_NID(fake_x509, NID_certificate_policies, -1);
	if (nPos != -1)
		X509_delete_ext(fake_x509, nPos);

	nPos = X509_get_ext_by_NID(fake_x509, NID_policy_constraints, -1);
	if (nPos != -1)
		X509_delete_ext(fake_x509, nPos);

	nPos = X509_get_ext_by_NID(fake_x509, NID_policy_mappings, -1);
	if (nPos != -1)
		X509_delete_ext(fake_x509, nPos);

	nPos = X509_get_ext_by_NID(fake_x509, NID_inhibit_any_policy, -1);
	if (nPos != -1)
		X509_delete_ext(fake_x509, nPos);

	X509_sign(fake_x509, rootkey, EVP_sha256());

	if (issuer)
		X509_NAME_free(issuer);

	return fake_x509;
}


/*============================================================
 * function declarations
 *============================================================*/
int find_target_address(char *uri,
        char *target_address,
        char *path,
        int *port);

void format_log_entry(char *logstring,
        int sock,
        char *uri,
        int size);

void *forwarder(void *args);

void *webTalk(void *args);

void secureTalk(int clientfd, rio_t client, char *inHost, char *version, int serverPort);

void ignore();

void debug_print(char* msg);

int debug;
int proxyPort;
int debugfd;
int logfd;
pthread_mutex_t mutex;

/* main function for the proxy program */

int main(int argc, char *argv[]) {
    int count = 0;
    int listenfd, connfd, clientlen, optval, serverPort, i;
    struct sockaddr_in clientaddr;
    struct hostent *hp;
    char *haddrp;
    sigset_t sig_pipe;
    pthread_t tid;
    int *args;

    if (argc < 2) {
        printf("Usage: ./%s port [debug] [webServerPort]\n", argv[0]);
        exit(1);
    }
    if (argc == 4)
        serverPort = atoi(argv[3]);
    else
        serverPort = 80;

    Signal(SIGPIPE, ignore);

    if (sigemptyset(&sig_pipe) || sigaddset(&sig_pipe, SIGPIPE))
        unix_error("creating sig_pipe set failed");
    if (sigprocmask(SIG_BLOCK, &sig_pipe, NULL) == -1)
        unix_error("sigprocmask failed");

    proxyPort = atoi(argv[1]);

    if (argc > 2)
        debug = atoi(argv[2]);
    else
        debug = 0;


    /* start listening on proxy port */

    listenfd = Open_listenfd(proxyPort);
    if (listenfd < 0) {
    	exit(-1);
    }

    optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int));

    if (debug) debugfd = Open(DEBUG_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);

    logfd = Open(LOG_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);


    /* if writing to log files, force each thread to grab a lock before writing
       to the files */
    pthread_mutex_init(&mutex, NULL);

    while (1) {

        clientlen = sizeof(clientaddr);

        /* accept a new connection from a client here */
        connfd = Accept(listenfd, (SA *) &clientaddr, &clientlen);
        debug_print("New connection");

        pthread_t clientThread;

        args = malloc(sizeof(int) * 2);
        args[0] = connfd;
        args[1] = serverPort;

        Pthread_create(&clientThread, NULL, webTalk, (void*)args);
    }

    if (debug) Close(debugfd);
    Close(logfd);
    pthread_mutex_destroy(&mutex);

    return 0;
}

/**
 * Spawned when a new connection occurs
 * Determines type of connection and handles appropriately.
 */
void *webTalk(void *args) {
    int numBytes, lineNum, serverfd, clientfd, serverPort;
    int tries;
    int byteCount = 0;
    char firstRequest[MAXLINE];
    char buf1[MAXLINE], buf2[MAXLINE], buf3[MAXLINE];
    char host[MAXLINE];
    char url[MAXLINE], logString[MAXLINE];
    char *token, *cmd, *version, *file, *saveptr;
    rio_t server, client;
    char slash[10];
    strcpy(slash, "/");

    clientfd = ((int *) args)[0];
    serverPort = ((int *) args)[1];
    free(args);

    Rio_readinitb(&client, clientfd);

    /* Read the Request Header - GET/CONNECT/POST/etc. */
    numBytes = Rio_readlineb(&client, firstRequest, MAXLINE);

    if (numBytes <= 0 || firstRequest == NULL) {
    	debug_print("Invalid Request.");
    	return NULL;
    }

    strcpy(buf1, firstRequest);

    /* Splitting things apart - need to save state */
    char strtokState[MAXLINE];
    char * httpMethod;
    httpMethod = strtok_r(buf1, " ", &strtokState);

    if (httpMethod == NULL) {
    	debug_print("Invalid Request.");
    	return NULL;
    }

    if ((strcmp(httpMethod, "GET") == 0) || (strcmp(httpMethod, "HEAD") == 0)) {
    	/* Get the URL of the Request */
    	char * requestParts = strtok_r(NULL, " ", &strtokState);
    	if (requestParts == NULL) {
    		debug_print("Invalid Request.");
    		return NULL;
    	}

    	if (find_target_address(requestParts, host, url, &serverPort) < 0) {
    		debug_print("Could not Parse Request.");
    		return NULL;
    	}
		/* better naming */
    	file = url;

    	/* Get the HTTP Version used */
    	char * httpVersion = NULL;

    	httpVersion = strtok_r(NULL, " ", &strtokState);
    	/* sometimes httpVersion is not specified by the client */
    	if (httpVersion == NULL) {
    		/* just make the httpVersion by \r\n for valid headers */
    		httpVersion = "\r\n";
    	}

    	serverfd = -1;
    	int connectionAttempts = 0;

    	/* connect until we succeed */
    	/* or if we exceed MAX_CONNECTION_ATTEMPTS - then exit */
    	while (serverfd < 0) {
    		if (connectionAttempts > MAX_CONNECTION_ATTEMPTS) {
				fprintf(stderr, "Could not connect to: %s\n", host);
				return NULL;
			}
    		serverfd = Open_clientfd(host, serverPort);
    		connectionAttempts++;
    	}

		Rio_readinitb(&server, serverfd);

		/* reformat the new GET header */
		sprintf(buf2, "%s %s %s", httpMethod, file, httpVersion);
		Rio_writen(serverfd, buf2, strlen(buf2));

		fprintf(stdout, "Raw Header: %s", firstRequest);
    	fprintf(stdout, "New Header: %s", buf2);

		/* while we haven't read the last line - the end of the request */
		while (strcmp(buf2, "\r\n") > 0) {
			/* wipe memory */
			memset((void*)buf2, 0, MAXLINE);

			/* read new header from client */
			byteCount = Rio_readlineb(&client, buf2, MAXLINE);

			if (byteCount < 0 || buf2 == NULL) {
				debug_print("Did not receive header from client.");
				return NULL;
			}

			if (strstr(buf2, "Keep-Alive:") || strstr(buf2, "Proxy-Connection: ") || strstr(buf2, "Connection: ")) {
				/* don't send this at all - we don't likes it my precious */
			}
			else {
				if (strcmp(buf2, "\r\n") == 0) {
					sprintf(buf2, "Connection: close\r\n");
					/* pop in a Connection: close header for good luck. */
					Rio_writen(serverfd, buf2, strlen(buf2));
					sprintf(buf2, "\r\n");
				}

				/* update length of string in case of modifications to header */
				fprintf(stderr, "%s", buf2);
				Rio_writen(serverfd, buf2, strlen(buf2));
			}
		}

		/* client sent last blank line in header requests - shutdown server connection */

		debug_print("Sent Headers - now receiving");

		do {
			/* read the data from the server */
			byteCount = Rio_readp(serverfd, buf3, MAXLINE);
			/* send it to the client */
			Rio_writen(clientfd, buf3, byteCount);
		}
		while (byteCount > 0);
		/* Means EOF: shutdown sending to client */
		shutdown(clientfd, 1);
		/* NOTE: shutting down the server first causes problems with some websites. Esp cloudfare, etc. */
		shutdown(serverfd, 1);
		debug_print("Transferred.");
    }
    else {
    	if (strcmp(httpMethod, "CONNECT") == 0) { 
		
		       /* CONNECT是代理协议 */
			
			/* need to parse this request */
			char * requestServer = strtok_r(NULL, " ", &strtokState);

			/* read the port and hostname */
			char * serverAddress = strtok(requestServer, ":");
			if (serverAddress == NULL) {
				return NULL;
			}
			fprintf(stdout, "CONNECT - %s\n", requestServer);

			char * port = strtok(NULL, " ");
			if (port == NULL) {
				port = "443";
			}
			serverPort = atoi(port);

			/* get the HTTP version */
			char * httpVersion = strtok_r(NULL, " ", &strtokState);
			httpVersion[strlen(httpVersion) - 2] = '\0';

			secureTalk(clientfd, client, serverAddress, httpVersion, serverPort);
    	}
    	else {
    		/* a different HTTP request - POST, etc */
    		fprintf(stderr, "Unsupported request: %s\n", httpMethod);
    	}
    }
    return NULL;
}

/*[liuzhuan] */
void SSLTerminal(SSL *ssl) 
{
	SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	if (ctx) {
		SSL_CTX_free(ctx);
	}
}

/* this function handles the two-way encrypted data transferred in
   an HTTPS connection */

void secureTalk(int clientfd, rio_t client, char *inHost, char *version, int serverPort) 
{
    int serverfd = 0, numBytes1 = 0, numBytes2 = 0;
    int tries = 0;
    rio_t server;
    char buf1[MAXLINE] = {0}, buf2[MAXLINE] = {0};
    pthread_t tid;
    int *args;

    if (serverPort == proxyPort)
        serverPort = 443;

    /* connect to the server */
    tries = 0;
    while (tries < MAX_CONNECTION_ATTEMPTS) {
    	serverfd = Open_clientfd(inHost, serverPort);
    	if (serverfd >= 0) {
    		break;
    	}
    }

    /* clientfd is browser */
    /* serverfd is server */
    Rio_readinitb(&server, serverfd);

    /* let the client know we've connected to the server */
    //sprintf(buf1, "%s 200 OK\r\n\r\n", version);
	/* 回复客户端代理协议 200, 表示ok */
    sprintf(buf1, "%s 200 Connection Established\r\n\r\n", version);
    Rio_writen(clientfd, buf1, strlen(buf1));

    /*[liuzhuan] 加SSL流程 */
    printf("------------- Line num %d -------------\n", __LINE__);
    int ret;
    struct ppSSL PSL;
    SSL_library_init();
    SSL_load_error_strings();

    /* [liuzhuan] 从对端方向(server socket direction) 建立假证书 */
    SSL_CTX * ctx_server;
    ctx_server = SSL_CTX_new(TLSv1_2_client_method());
    PSL.ssl_server = SSL_new(ctx_server);
    ret = SSL_set_fd(PSL.ssl_server, serverfd);
    ret = SSL_set_tlsext_host_name(PSL.ssl_server, inHost);
    if( SSL_connect(PSL.ssl_server) < 0) 
    {
		printf("SSL_connect failed\n");
		return;
	}
    EVP_PKEY * serverKey = createServerKey();
	EVP_PKEY * rootKey = createRootKey();
    X509 * fake_x509 = createFakeCertificate(PSL.ssl_server, serverKey, rootKey);
    
    /* [liuzhuan] 从对端方向(client socket direction) 建立假证书 */
    SSL_CTX * ctx_client;
    ctx_client = SSL_CTX_new(SSLv23_server_method());
    ret = SSL_CTX_use_certificate(ctx_client, fake_x509);
    ret = SSL_CTX_use_PrivateKey(ctx_client, serverKey);
    ret = SSL_CTX_check_private_key(ctx_client);
    PSL.ssl_client = SSL_new(ctx_client);
    ret = SSL_set_fd(PSL.ssl_client, clientfd);
    if( SSL_accept(PSL.ssl_client) != 1 )
    {
        printf("SSL_accept failed\n");
		return;
    }

    /* [liuzhuan] 中间是代理 */
    /* [liuzhuan]  SSLv23_server_method()用于SSL_accept && TLSv1_2_client_method()用于SSL_connect */
    /* [liuzhuan] to--server 方向使用SSL_connect */
    /* [liuzhuan] to--client 方向使用SSL_accept */

    /* [liuzhuan] 加参数到线程的穿参 */
	PSL.clientfd = clientfd;
	PSL.serverfd = serverfd;

	/* [liuzhuan] 建立server-->client线程, forwarder() */
    Pthread_create(&tid, NULL, forwarder, (void*)&PSL);

    /* [liuzhuan] process bytes from client -> server */
    while (1) {
        numBytes1 = SSL_read(PSL.ssl_client, buf1, MAXLINE);
        if (numBytes1 <= 0) {
    		/* EOF - quit connection */
            break;
        }
        numBytes2 = SSL_write(PSL.ssl_server, buf1, numBytes1);
        if (numBytes1 != numBytes2) {
    		/* did not write correct number of bytes */
            fprintf(stderr, "Did not send correct number of bytes to server.\n");
            break;
        }
    }
   
    /* join forwarder thread */
    Pthread_join(tid, NULL);

    SSLTerminal(PSL.ssl_server);
    SSLTerminal(PSL.ssl_client);
    close(PSL.clientfd);
    close(PSL.serverfd);
    X509_free(fake_x509);
}

/* SSL通道版本->select IO (ssl read ret code mode)模式 */
void * forwarder(void * args) 
{
    fd_set readfds;
    char buf1[MAXLINE * 2] = {0};
    struct ppSSL * PSL = (struct ppSSL *)args;
    int numBytes = 0;
    int byteCount = 0;

    int error = 0;
    int code = 0;

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(PSL->serverfd, &readfds);
        if( select(FD_SETSIZE, &readfds, NULL, NULL, NULL) == 0  )
        {
            continue;
        }

        if( FD_ISSET(PSL->serverfd, &readfds) )
        {
            numBytes = SSL_read(PSL->ssl_server, buf1, MAXLINE * 2);
            
            code = numBytes;
            error = SSL_get_error(PSL->ssl_server, code);
            if( error == SSL_ERROR_ZERO_RETURN )
            {
                fprintf(stderr, "SSL_ERROR_ZERO_RETURN.\n");
                break;
            }

            byteCount = SSL_write(PSL->ssl_client, buf1, numBytes);
	        if (numBytes != byteCount) 
            {
    			fprintf(stderr, "Did not send correct number of bytes to client.\n");
	        }
        }
    }

    return NULL;
}

/* SSL通道版本->select IO模式 */
/*
void * forwarder(void * args) 
{
    fd_set readfds;
    char buf1[MAXLINE] = {0};
    struct ppSSL * PSL = (struct ppSSL *)args;
    int numBytes = 0;
    int byteCount = 0;
    
    int wflag = 1;

    while(wflag)
    {
        FD_ZERO(&readfds);
        FD_SET(PSL->serverfd, &readfds);
        if( select(FD_SETSIZE, &readfds, NULL, NULL, NULL) == 0  )
        {
            continue;
        }

        if( FD_ISSET(PSL->serverfd, &readfds) )
        {
            do
            {
                numBytes = SSL_read(PSL->ssl_server, buf1, MAXLINE);
                if (numBytes <= 0) 
                {
                    fprintf(stderr, "Did not recv correct number of bytes to server.\n");
                    wflag = 0;
        			break;
        		}
                byteCount = SSL_write(PSL->ssl_client, buf1, numBytes);
		        if (numBytes != byteCount) 
                {
        			fprintf(stderr, "Did not send correct number of bytes to client.\n");
                    wflag = 0;
		        	break;
		        }
                                
            } while ( SSL_pending(PSL->ssl_server) );
        }
    }

    return NULL;
}
*/


/* SSL通道版本->普通 SSL IO 模式 */
/*
void * forwarder(void * args) 
{
    int numBytes = 0;
    int lineNum = 0;
    int byteCount = 0;
    char buf1[MAXLINE] = {0};

    struct ppSSL * PSL = (struct ppSSL *)args;

	while (1) 
    {
        memset(buf1, 0, MAXLINE);

		numBytes = SSL_read(PSL->ssl_server, buf1, MAXLINE);
		if (numBytes <= 0) {
			break;
		}

        numBytes = SSL_pending(PSL->ssl_server);

		byteCount = SSL_write(PSL->ssl_client, buf1, numBytes);
		if (numBytes != byteCount) {
			fprintf(stderr, "Did not send correct number of bytes to client.\n");
			break;
		}
	}

	return NULL;
}
*/

/* IO通道版本->普通 read/write IO 模式 */
/*
void * forwarder(void * args)
{
    int numBytes, lineNum, serverfd, clientfd;
    int byteCount = 0;
    char buf1[MAXLINE] = {0};
    struct ppSSL * PSL = (struct ppSSL *)args;

	while (1) 
    {
        memset(buf1, 0, MAXLINE);

		numBytes = Rio_readp(PSL->serverfd, buf1, MAXLINE);
		if (numBytes <= 0) {
			break;
		}
		byteCount = Rio_writen(PSL->clientfd, buf1, numBytes);
		if (numBytes != byteCount) 
        {
			fprintf(stderr, "Did not send correct number of bytes to client.\n");
			break;
		}
	}

	return NULL;
}
*/

void ignore() {
    return;
}


/*============================================================
 * url parser:
 *    find_target_address()
 *        Given a url, copy the target web server address to
 *        target_address and the following path to path.
 *        target_address and path have to be allocated before they 
 *        are passed in and should be long enough (use MAXLINE to be 
 *        safe)
 *
 *        Return the port number. 0 is returned if there is
 *        any error in parsing the url.
 *
 *============================================================*/

/*find_target_address - find the host name from the uri */
int find_target_address(char *uri, char *target_address, char *path,
        int *port) {
    //  printf("uri: %s\n",uri);


    if (strncasecmp(uri, "http://", 7) == 0) {
        char *hostbegin, *hostend, *pathbegin;
        int len;

        /* find the target address */
        hostbegin = uri + 7;
        hostend = strpbrk(hostbegin, " :/\r\n");
        if (hostend == NULL) {
            hostend = hostbegin + strlen(hostbegin);
        }

        len = hostend - hostbegin;

        strncpy(target_address, hostbegin, len);
        target_address[len] = '\0';

        /* find the port number */
        if (*hostend == ':') *port = atoi(hostend + 1);

        /* find the path */

        pathbegin = strchr(hostbegin, '/');

        if (pathbegin == NULL) {
            path[0] = '\0';

        }
        else {
        	// TODO: Removed this, why was it here? are things going to explode?!
            //pathbegin++;
            strcpy(path, pathbegin);
        }
        return 0;
    }
    target_address[0] = '\0';
    return -1;
}


/*============================================================
 * log utility
 *    format_log_entry
 *       Copy the formatted log entry to logstring
 *============================================================*/

void format_log_entry(char *logstring, int sock, char *uri, int size) {
    time_t now;
    char buffer[MAXLINE];
    struct sockaddr_in addr;
    unsigned long host;
    unsigned char a, b, c, d;
    socklen_t len = sizeof(addr);

    now = time(NULL);
    strftime(buffer, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    if (getpeername(sock, (struct sockaddr *) &addr, &len)) {
        /* something went wrong writing log entry */
        printf("getpeername failed\n");
        return;
    }

    host = ntohl(addr.sin_addr.s_addr);
    a = host >> 24;
    b = (host >> 16) & 0xff;
    c = (host >> 8) & 0xff;
    d = host & 0xff;

    sprintf(logstring, "%s: %d.%d.%d.%d %s %d\n", buffer, a, b, c, d, uri, size);
}

void debug_print(char* msg) {
	fprintf(stdout, "%s\n", msg);
}
