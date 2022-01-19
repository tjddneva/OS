#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
void parse_path(const char *path_name, char *dir, char *file_name);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  buffer_cache_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  free_map_close ();
  buffer_cache_terminate ();
}

bool
filesys_create (const char *path, off_t initial_size)
{
  block_sector_t inode_sector = 0;

  // split path and name
  char directory[ strlen(path) ];
  char file_name[ strlen(path) ];
  parse_path(path, directory, file_name);
  struct dir *dir = dir_open_path (directory);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, file_name, inode_sector));

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  dir_close (dir);

  return success;
}

bool
filesys_create_dir (const char *path)
{
  block_sector_t inode_sector = 0;

  char parent_directory[strlen(path)];
  char child_directory[strlen(path)];
  parse_path (path, parent_directory, child_directory);
  struct dir *dir = dir_open_path(parent_directory);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
				  &&dir_create(inode_sector,16,inode_get_inumber(dir_get_inode(dir)))
                  && dir_add (dir, child_directory, inode_sector));

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
    
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  int l = strlen(name);
  if (l == 0) return NULL;

  char directory[ l + 1 ];
  char file_name[ l + 1 ];
  parse_path(name, directory, file_name);
  struct dir *dir = dir_open_path (directory);
  struct inode *inode = NULL;

  // removed directory handling
  if (dir == NULL) return NULL;

  if (strlen(file_name) > 0) {
    dir_lookup (dir, file_name, &inode);
    dir_close (dir);
  }
  else { // empty filename : just return the directory
    inode = dir_get_inode (dir);
  }

  // removed file handling
  if (inode == NULL || inode_is_removed (inode))
    return NULL;

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  char directory[ strlen(name) ];
  char file_name[ strlen(name) ];
  parse_path(name, directory, file_name);
  struct dir *dir = dir_open_path (directory);

  bool success = (dir != NULL && dir_remove (dir, file_name));
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");

  free_map_close ();
  printf ("done.\n");
}


void
parse_path(const char *path_name,
    char *dir, char *file_name)
{

  int l = strlen(path_name);
  char *s = (char*) malloc( sizeof(char) * (l + 1) );
  memcpy (s, path_name, sizeof(char) * (l + 1));

  if(l > 0 && path_name[0] == '/') {
    if(dir) *dir++ = '/';
  }

  // tokenize
  char *token, *p, *last_token = "";
  for (token = strtok_r(s, "/", &p); token != NULL;
       token = strtok_r(NULL, "/", &p))
  {
    // append last_token into directory
    int tl = strlen (last_token);
    if (dir && tl > 0) {
      memcpy (dir, last_token, sizeof(char) * tl);
      dir[tl] = '/';
      dir += tl + 1;
    }

    last_token = token;
  }

  if(dir) *dir = '\0';
  memcpy (file_name, last_token, sizeof(char) * (strlen(last_token) + 1));
  free (s); 
}
