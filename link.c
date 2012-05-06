/*
 * Copyright (c) 2012 Andreas Fett.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>

#include "link.h"

struct link* link_array_add(struct link_array *links)
{
	++links->count;
	links->link = realloc(links->link,
		links->count * sizeof(struct link));
	return &links->link[links->count - 1];
}

bool link_array_foreach(struct link_array *links, link_array_fun *fun, void *aux)
{
	int i;
	for (i = 0; i < links->count; ++i) {
		if (!fun(&links->link[i], aux)) {
			return false;
		}
	}

	return true;
}

void link_array_filter(struct link_array *links, link_array_keep *keep, void *aux)
{
	size_t i;

	i = 0;
	while (i < links->count) {
		if (keep(&links->link[i], aux)) {
			++i;
			continue;
		}

		--links->count;
		if (links->count != i) {
			memcpy(&links->link[i],
				&links->link[links->count],
				sizeof(struct link));
		}
	}

	if (links->count != 0) {
		links->link = realloc(links->link,
			links->count * sizeof(struct link));
	} else {
		free(links->link);
		links->link = NULL;
	}
}

void link_array_free(struct link_array *links)
{
	free(links->link);
	links->link = NULL;
	links->count = 0;
}
