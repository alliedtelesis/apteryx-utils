/**
 * @file apteryx_sync.h
 *
 * Header file for Apteryx syncer utility
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#ifndef _APTERYX_SYNC_H_
#define _APTERYX_SYNC_H_
#include <apteryx.h>

/* Apteryx sync path was previously defined in apteryx.h, so protect old Apteryx version.
 * apteryx.h included above to ensure that there can't be a mismatch. */
#ifndef APTERYX_SYNC_PATH
#define APTERYX_SYNC_PATH "/apteryx-sync"
#endif /* !APTERYX_SYNC_PATH */

#define APTERYX_SYNC_DESTINATIONS_PATH APTERYX_SYNC_PATH "/destinations"
/* To Add/update a destination for the Apteryx syncer use the following:
 * apteryx_set_string (APTERYX_SYNC_DESTINATIONS_PATH, dest_name, dest_url);
 *
 * Use NULL dest_url to remove destination
 */

#endif /* _APTERYX_SYNC_H_ */
