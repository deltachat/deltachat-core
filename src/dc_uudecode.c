/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 ******************************************************************************/

/**
 * For module testing activate  __DEBUG__ and __TESTING__
 */

//#define __DEBUG__
//#define __DEBUG_VERBOSE__

/**
 *  __TESTING__ is used for local development
 *              --> comment this out for testing
 */
//#define __TESTING__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef  __TESTING__
	#include "dc_tools_test.h"
#else
    #include "dc_context.h"
	#include "dc_tools.h"
#endif

#include "dc_uudecode.h"


/**
 *  Locally needed function declarations
 *  This makes the order of function definitions independent from first use
 */

/* return hex representation of a string*/
char* _print_hex(char* s);

/* delivers one line from a string */
int   dc_getline (char** line, char* source, char** nextchar);


/* checks if line matches uuencoded rules */
int   dc_uu_check_line(int n, int line_len);

/* find uuencoded part in msgtxt and returns it's position */
char* dc_find_uuencoded_part (const char* msgtxt);

/* extract uuencoded part and make it for next func available */
char* dc_handle_uuencoded_part (const char*   msgtxt,
								 char*         uu_msg_start_pos,
								 char**        ret_binary,
								 size_t*       ret_binary_bytes,
								 char**        ret_filename);

/* decode uuencoded part and provide it, used in mr_handle_uuencoded_part() */
int   dc_uudecode(char** ret_binary, size_t uudecoding_buffer_len, const char* uu_body_start);



/**
 *  Variables and preprocessor definitions
 */

#define LF   "\n"   //10



#ifdef __DEBUG__
	char in[100]; // for gets()
#endif


/**
 *  Function defintions
 */


/**
 * This function takes a text and returns this text stripped by the first uuencoded part;
 * the uuencoded part itself is returned by three return parameters.
 *
 * If there are no uuencoded parts, the function terminates fast by returning NULL.
 *
 * @param text Null-terminated text to search uuencode parts in.
 *     The text is not modified, instead, the modified text is returned on success.
 *
 * @param[out] ret_binary Points to a pointer that is set to the binary blob on
 *     success.
 *     The data is allocated with malloc() and must be free()'d by the caller.
 *     If no uuencoded part is found, this parameter is set to NULL and the function returns NULL.
 *
 * @param[out] ret_binary_bytes Points to an integer that should be set to
 *     binary blob bytes on success.
 *
 * @param[out] ret_filename Points to a pointer that should be set to the filename of the blob.
 *     The data is allocated with malloc() and must be free()'d by the caller.
 *     If no uuencoded part is found, this parameter is set to NULL and the function returns NULL.
 *
 * @return If uuencoded parts are found in the given text, the function returns the
 *     given text stripped by the first uuencode block.
 *     The caller will call mruudecode_do() again with this remaining text then.
 *     This way, multiple uuencoded parts can be stripped from a text.
 *     If no uuencoded parts are found or on errors, NULL is returned.
 */
char* dc_uudecode_do(const char* text, char** ret_binary, size_t* ret_binary_bytes, char** ret_filename)
{
	// CAVE: This function may be called in a loop until it returns NULL, so make sure not to create an invinitive look.

	if( text == NULL || ret_binary == NULL || ret_binary_bytes == NULL || ret_filename == NULL ) {
		goto cleanup; // bad parameters
	}

	char* uustartpos    = NULL;
	char* ret_msg_text  = NULL; // NULL = no uuencoded parts are found (standard case)
	
	// first make a quick check if a part exists
	uustartpos = dc_find_uuencoded_part(text);
	if (!uustartpos){
		#ifdef __DEBUG__
		puts("no or no further uu_part found\n\n");
		puts("printing now message after all dc_handle_uuencoded_part(s)\n\n");
		gets(in);
		puts(text);
		#endif

		// no or no further uuencoded parts found
		goto cleanup;
	}

	#ifdef __DEBUG__
	printf("uu_part found at pos: %.50s [......]\n\n", uustartpos);
	#endif

	/**
	 * todo: identify first call of this function to unify buffer only once
	 *
	 * prepare buffer
	 * first unify buffer
	 */
	char* txt = strdup(text);
	dc_unify_lineends(txt);

	// find again in new buffer
	uustartpos = dc_find_uuencoded_part(txt);
	if (uustartpos){
		// then handle uuencoded part
		ret_msg_text = dc_handle_uuencoded_part (txt, uustartpos, ret_binary, ret_binary_bytes, ret_filename);
	}
	free(txt);
	
	#ifdef __DEBUG__
	  puts("printing now remaining message after dc_handle_uuencoded_part() call\n\n");
	  gets(in);
	  puts("go ...\n\n");
	#endif

	return ret_msg_text;
	

cleanup:

	return NULL;
}




/***********************************************************************
 *  From here on new code follows
 *
 *  This is version 4 of the dc_uudecode.c
 * 	It the api which is used in  dc_mimeparser.c  of the original project
 *  and works now with unified line ends only (LF).
 * 
 */ 



/***********************************************************************
 *  Helper functions
 */

char* dc_print_hex (char* s){
	/**
	 * make hex representation of a string
	 * 
	 * @Return
	 *      hex representation of s (needs to be free'd)
	 * 
	 */
	int n = strlen(s);
	int i;
	char* hex = (char*)calloc((2*n+1), sizeof(char));
	
	for(i = 0; i<n; i++){
		sprintf(hex+i*2, "%02X", s[i]);
	}
	
	return hex;
	
} //dc_print_hex()



// todo: replace by strtok_r ??? ==> no, strtok_r modifies source string!

int dc_getline (char** ret_lineptr, char* source, char** ret_nextcharptr){
	/**
	 * 	Extracts first line from a given string (source)
	 * 
	 * 	Instead of strtok_r it doesn't manipulate the input string 
	 *
	 *  Parameters:
	 * 
	 *  @ret_lineptr   - returned line incl. line end char
	 *  @source        - input string (will not be changed)
	 *  @ret_nextchar  - pointer to next char after current line end
	 *                   gives start ptr for next call of this function
	 * 
	 *  @Return: 
	 *      strlen of line found (incl. line end char(s) but excluding '\0')
	 *      0 if no line is read
	 */
	 
	char* lineend   = source;
	char* start     = source;
	int   linelen   = 0;

	*ret_lineptr = NULL;
	
	//printf( "dc_getline - %d %d\n", (int)source, (int)start);
	
	if((lineend = strstr(start, LF))){
		//printf("  dc_getline - Line End found\n");
		
		lineend++; // this belongs to the line
		
		linelen = lineend - start; // len of line

		//printf("  dc_getline - linelen=%d\n", linelen);
		//printf("  dc_getline - first 7 chars=%.7s [...]\n", start);
		
		*ret_nextcharptr = lineend;
		
		*ret_lineptr = strndup(start, linelen);
		
		#ifdef __DEBUG_VERBOSE__
		if( *ret_lineptr != NULL ){
			printf("  ** dc_getline - complete line found= (see below!)\n%s\n", *ret_lineptr);
		}
		#endif
	}
	
	return linelen;
} //dc_getline()



int dc_uu_check_line (int n, int line_len){
	/**
	 *	Checks if n describes the correct line length for given encoded len char line len
	 * 
	 *  Parameters:
	 * 
	 *  @n        - number of encoded bytes in a line
	 *  @line_len - number of chars in encoded string with first len char
	 * 
	 *  example uuencoded line where n is 45 and 1st char describes this:
	 * 
	 *     M9&%T``!3"F6(A '_F5V2'G']1(A5%)L-,KFI!G+OR#70]]L'X8H`?S S2I@P
	 *     ||
	 *     |+-- from here data
	 *     +--- len char
	 * 
	 * 	@returns -	1 if line is ok
	 * 				0 otherwise
	 */
	 
	/* Calculate expected # of chars and pad if necessary */
	int expected;
	
	if (n > 0){
		expected = (n+2)/3*4;
	}
	else
		return 0;

	/* # of chars + len char is the expected line len*/
	return (line_len == expected + 1) ? 1 : 0;
	
} //dc_uu_check_line()


/**
 *      Main uudecoding functions
 */ 

char* dc_find_uuencoded_part (const char* msgtxt){
	/**
	 *  Find uuencoded part in msgtxt & return it's position.
	 *  If no part is found NULL is returned.
	 */
	 
	char* uu_part_pos = NULL;
	
	char* tofind = "begin ";

	if ((uu_part_pos = strstr(msgtxt, tofind))){
		if (strncmp((uu_part_pos+9), " ", 1) == 0){ 
			// check here the second space too "begin 666 filename"
			//uu_part_pos++; //go after the LF (if searching for LF before 'begin ')
			#ifdef __DEBUG__
			printf("uu encoded part roughly found at %d\n", (int)(uu_part_pos - msgtxt));
			gets(in);
			#endif
			
			return uu_part_pos;
		}
	}
	
	// no uuencoded text part identified
	return NULL;
	
} //dc_find_uuencoded_part()


char* dc_handle_uuencoded_part (const char*   msgtxt,
								 char*         uu_msg_start_pos,
								 char**        ret_binary,
								 size_t*       ret_binary_bytes,
								 char**        ret_filename){
	/**
	 *  Handle first (!) uuencoded part in a msg
	 * 
	 * Parameters:
	 * 
	 *  @msgtxt           - original msg
	 *  @uu_msg_start_pos - start position of uuencoded part of msg
	 *  @ret_binary       - returned uudecoded data block (to be free'd)
	 *  @ret_binary_bytes - len of ret_binary.
	 *                      In case of error 0 is returned.
	 *  @ret_filename     - detected filename from uuencoded data block (to be free'd)
	 *                      In case of error NULL is returned
	 *
	 *  @return          - msgtxt stripped by first uuencoded part.
	 *                      Stripping will be done whenever possible.
	 *						In case of any error:
	 * 						 * return code = NULL
	 * 						 * ret_binary = NULL
	 * 						 * ret_binary_bytes = 0
	 * 						
	 * 
	 * 
	 * Steps:
	 * 
	 *  1) verify start line and extract filename
	 *  2) search for end of uu_part
	 *      calculate size of uuencoded data block
	 *      malloc memory for new message and uudecoded data block
	 *  3) decode uu_part
	 *       use mr_uudecode() for decoding
	 *  4) replace uu_part in original message text by a link to file
	 *  5) return stripped msgtxt for next loop (one loop handles one uu_part)
	 *
	 *     If only one uu_part is in msg then next loop will be quick :-)
	 */
	
	/**
	 *      1) verify start line and extract filename
	 */ 
	int   mode;
	char  filename[200] = "";
	char* line;
	
	char* uu_body_start;
	char* uu_body_end;
	
	char* ret_msgtxt;
	int   nread;
	
	/* build format for first uuencoded line scan*/
	char* SSCANF_FORMAT = "begin %o %[^\n]";
	
	/* get and check 1st uuencoded start line*/
	nread = dc_getline(&line, uu_msg_start_pos, &uu_body_start);
	if(line && (nread > 0)){
		sscanf (line, SSCANF_FORMAT, &mode, filename);
		#ifdef __DEBUG__
		printf ("dc_handle_uuencoded_part - mode=%o, filename=%s\n", mode, filename);
		#endif
		free(line); line = NULL;

		int len_filename = strlen(filename);
		
		if(0 < mode && mode <= 777 && len_filename){
			#ifdef __DEBUG__
			printf ("dc_handle_uuencoded_part - uu_part verified\n");
			#endif
			
			*ret_filename = strdup(filename);
		}
		else{
			#ifdef __DEBUG__
			printf("dc_handle_uuencoded_part - this is not an uu_part, stopping here!\n");
			#endif
			
			*ret_binary_bytes = 0;
			*ret_filename = NULL;
		
			return NULL;
		}
	}
	else{
		*ret_binary_bytes = 0;
		*ret_filename = NULL;
		
		return NULL;
	}
	
	/**
	 *      2) search for end of uuencoded part
	 * 
	 *   There are two possible ends defined:
	 *     a) with a 'back quote'  and  (standard)
	 *     b) with a 'blank char'       (not handled here!, future?)
	 */
	 
	/* build end pattern for uuencoded part*/
	char* uu_end_pattern = "`\nend\n";
	
	int uu_end_len = strlen(uu_end_pattern);

	#ifdef __DEBUG__
	printf("dc_handle_uuencoded_part - uu_end_pattern=%s", uu_end_pattern);
	#endif
	
	if((uu_body_end = strstr(uu_body_start, uu_end_pattern))){
		uu_body_end += uu_end_len;
		#ifdef __DEBUG__
		printf("dc_handle_uuencoded_part - Line End found, len=%d\n", (int)(uu_body_end - uu_body_start));
		#endif
	}
	else{
		*ret_binary_bytes = 0;
		*ret_filename = NULL;
		
		return NULL;
	}
	
	
	/**
	 *      3) Decode uuencoded part
	 */
	int uu_body_len = uu_body_end - uu_body_start;
	

	/*  This is a rough but high estimation because 3 binary bytes are
	 *  encoded in 4 chars (+ length char, + end_of_line_pattern, for each line ! )
	 *  Enough memory in each case :)
	 */
	int uudecoding_buffer_len = uu_body_len * 3 / 4;
	
	/* provide memory for decoding */
	*ret_binary = (char*) malloc(sizeof(char) * uudecoding_buffer_len );
	
	if (*ret_binary){
		*ret_binary_bytes = dc_uudecode(ret_binary, uudecoding_buffer_len, uu_body_start); 
		/**
		 *  uudecoded data can be worked here
		 *   store, print, returned or whatever ...
		 * 
		 *   it is returned here by ret_binary and *ret_binary_bytes func parameter !
		 */
		#ifdef __DEBUG__
		printf("rbb %d\n", (int)*ret_binary_bytes);
		#endif
	}
	
	/**
	 *      4) Replace uuencoded part in original message by a hint to the filename
	 * 
	 *		Do this in each case without respect of uudecoding result.
	 * 		In case of an error *ret_binary_bytes is 0, but uuencoded part
	 * 		 is stripped in each case.
	 */ 

	int first_part_len = uu_msg_start_pos - msgtxt;
	
	ret_msgtxt  = (char*) malloc( sizeof(char) * strlen(msgtxt) );

	// keep first part
	strncpy(ret_msgtxt, msgtxt, first_part_len);
	ret_msgtxt[first_part_len] = '\0';


	if(*ret_binary_bytes > 0){
		// set hint for uuencoded message part
		sprintf(&ret_msgtxt[first_part_len], "[uuencoded attachment] - filename: %s\n", filename);
	}else{
		// set hint for bad uuencoded message part
		sprintf(&ret_msgtxt[first_part_len], "[error in uuencoded attachment] - filename: %s\n", filename);
	}
	
	// concat remaining part
	strcat(ret_msgtxt, uu_body_end );
	
	return ret_msgtxt;
	
} //dc_handle_uuencoded_part()



/* Single character decode.  */
#define	DEC(c)	(((c) - ' ') & 077)

int dc_uudecode(char** ret_binary, size_t uudecoding_buffer_len, const char* uu_body_start){
	/**
	 *  Decode uuencoded part and provide it. Used in dc_handle_uuencoded_part
	 * 
	 *  Parameters:
	 * 
	 *  @ret_binary              - buffer where to write decoded data
	 *  @uudecoding_buffer_len   - len of buffer of ret_binary
	 *  @uu_body_start           - string with uuencoded data
	 * 
	 *  @return                 - number of decoded bytes
	 *                             In case of any error 0 is returned
	 */
	
	char* line;
	
	int   line_len;
	
	char* nextlinestart = (char*)uu_body_start;

	// line decoding
	char* p;
	char  ch;
	int   n;
	int   backquote_found = 0;
	int   ret_decoded_bytes = 0;


	/* open stream for output*/
	FILE *fp = open_memstream(ret_binary, &uudecoding_buffer_len);


	/**
	 *  decoding line by line
	 */
	while( (line_len = dc_getline (&line, nextlinestart, &nextlinestart)) ){
		/**
		 *       Documentation of uuencoded lines
		 * 
		 *  - First char of line gives number of encoded bytes per line
		 *    A standard line encodes 45 bytes of data.
		 *    (45 encoded bytes means 60 chars per line, 61 chars in summary)
		 *    "M........." means 45 bytes encoded / 60 chars are following
		 * 
		 *  - Every 4 char's block encodes 3 bytes of binary data,
		 *     that means that number of chars in each line needs to be a multiple of 4 (!).
		 *    This may be checked.
		 *  
		 *  - Each char's lower 6 bits are used for encoding.
		 * 
		 *  - Special handling for last line which may not encode full 3 bytes bunch 
		 */

		#ifdef __DEBUG__
		//printf("  dc_uudecode - line = %s\n", line);
		//gets(in);
		#endif

		/* 1st: test for end of uuencoded data */
		if( 0 == strncmp(line, "`", 1) && (line_len - 1) == 1){
			/* first line of end of uuencoded part found */

			//printf("  dc_uudecode -     *** single backquote found ***\n");
			backquote_found = 1;

			continue;
		}
		if( backquote_found && 0 == strncmp(line, "end", 3)){
			/* end of uuencoded part found */

			//printf("  dc_uudecode -     *** end of uuencoded part found ***\n");
			//fputs("This is for testing only. No uuencoded data. End of uuendcoded data detected!\n", fp);

			break;
		}
		
		/**
		 *  2nd: Decoding one line 
		 * 
		 *   (source partly from uudecode.c (GNU, Free Software Foundation)) 
		 */

		/* For each input line: */
		p = line;
		n = DEC (*p);  // n = number of encoded bytes

		// check line - compare given len with current line len
		// line[0] shows len info
		if (!dc_uu_check_line(n, line_len - 1)){

			char msg[120];

			sprintf(msg, "  dc_uudecode() -    *** stop decoding, invalid line len, N=%d, line_len=%d ***\n", n, (line_len - 1));

			#ifdef __DEBUG__
			puts(msg);
			#endif
			// write error msg to output file !
			fputs(msg, fp);
			ret_decoded_bytes = 0;
			break;
		}
		
		if (n <= 0){

			char msg[120];

			sprintf(msg, "  dc_uudecode() -    *** stop decoding, n <= 0, invalid line len %d ***\n", n);

			#ifdef __DEBUG__
			puts(msg);
			#endif
			// write error msg to output file !
			fputs(msg, fp);
			
			ret_decoded_bytes = 0;
			break;
		}

		//printf("  dc_uudecode -    n=%d\n", (int)n);
		
		if( ret_decoded_bytes < uudecoding_buffer_len - 3){
			// check for remaining buffer before decoding
			for (++p; n > 0; p += 4, n -= 3){
				if (n >= 3){
					ch = DEC (p[0]) << 2 | DEC (p[1]) >> 4;
					fputc((int)ch, fp);
					ret_decoded_bytes++;
					
					ch = DEC (p[1]) << 4 | DEC (p[2]) >> 2;
					fputc((int)ch, fp);
					ret_decoded_bytes++;
					
					ch = DEC (p[2]) << 6 | DEC (p[3]);
					fputc((int)ch, fp);
					ret_decoded_bytes++;
					
					//printf("  dc_uudecode -    full block decoded\n");
				}
				else{
					if (n >= 1){
						ch = DEC (p[0]) << 2 | DEC (p[1]) >> 4;
						fputc((int)ch, fp);
						ret_decoded_bytes++;
						//printf("  dc_uudecode -    n >= 1, n=%d decoded\n", n);
					}
					if (n >= 2){
						ch = DEC (p[1]) << 4 | DEC (p[2]) >> 2;
						fputc((int)ch, fp);
						ret_decoded_bytes++;

						//printf("  dc_uudecode -    n >= 2, n=%d decoded\n", n);
					}
				}
			}
		}
		free(line);

	}
	fclose(fp);
	
	return ret_decoded_bytes;
} // dc_uudecode()

