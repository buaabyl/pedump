/*  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef PYGETOPT_H_4F7A709E_70B3_11E6_92BF_005056C00008_INCLUDED_
#define PYGETOPT_H_4F7A709E_70B3_11E6_92BF_005056C00008_INCLUDED_

typedef struct {
    char* key;
    char* val;
}pygetopt_kv_t;

//opts.key and args eq NULL when at the tail of array.
typedef struct {
    int             opts_n;
    pygetopt_kv_t*  opts;
    int             args_n;
    char**          args;
}pygetopt_t;

//@brief
//  fmt  := "hf:"
//  lfmt := {"--help", "--file=", NULL}
//
//  commandline:
//      -h -f filename --help --file filename
//
//  int main(int argc, char* argv[]) 
//  {
//      ...
//      pygetopt_parse(argc-1, argv+1, fmt, NULL);
//      pygetopt_parse(argc-1, argv+1, NULL, lfmt);
//      pygetopt_parse(argc-1, argv+1, fmt, lfmt);
//      ...
//  }
//
pygetopt_t* pygetopt_parse(int argc, char** argv, const char* fmt, const char** lfmt);
void pygetopt_destroy(pygetopt_t* p);

int pygetopt_key_exists(pygetopt_t* cfg, const char* keyname);
const char* pygetopt_get_value(pygetopt_t* cfg, const char* keyname);

#endif

