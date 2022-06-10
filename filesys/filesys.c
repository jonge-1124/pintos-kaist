#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/fat.h"
#include "threads/thread.h"
#include "threads/palloc.h"



/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
	struct dir *root = dir_open_root();
	thread_current()->current_dir = root;

	dir_add(root, ".", dir_inode_sector(root));
	dir_add(root, "..", dir_inode_sector(root));
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	
	disk_sector_t inode_sector = 0;
	char *copy = palloc_get_page(PAL_ZERO);
	if (copy == NULL) return false;
	strlcpy(copy, name,strlen(name)+1);
	
	char *file_name = malloc(NAME_MAX + 1);
	if (file_name == NULL) return false;
	struct dir *dir = dir_parse(copy, file_name);
	if (dir == NULL) 
	{
		palloc_free_page(copy);
		free(file_name);
		return false;
	}
	
	cluster_t inode_cluster = fat_create_chain(0);
	if (inode_cluster != 0 ) inode_sector = cluster_to_sector(inode_cluster);
	
	bool success = (dir != NULL
			&& inode_cluster
			&& inode_create (cluster_to_sector(inode_cluster), initial_size, 1)
			&& dir_add (dir, file_name, inode_sector));
			
	if (!success && inode_sector != 0)
	{
		fat_remove_chain(inode_cluster, 0);
	}	
	
	dir_close (dir);
	free(file_name);
	palloc_free_page(copy);
	
	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	char *copy = palloc_get_page(PAL_ZERO);
	if (copy == NULL) return NULL;
	strlcpy(copy, name, strlen(name)+1);

	char *file_name = malloc(NAME_MAX + 1);
	struct dir *dir = dir_parse(copy, file_name);
	
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, file_name, &inode);
	dir_close (dir);
	
	palloc_free_page(copy);
	free(file_name);
	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	
	bool success;
	char *copy = palloc_get_page(PAL_ZERO);
	if (copy == NULL) return false;
	strlcpy(copy, name, strlen(name)+1);
	

	char *file_name = malloc(NAME_MAX + 1);
	if (file_name == NULL) return false;
	struct dir *dir = dir_parse(copy, file_name);
	

	struct inode *inode = NULL;
	if (dir != NULL) dir_lookup(dir, file_name, &inode);
	
	
	if (inode_is_file(inode))
	{
		
		success = (dir != NULL) && dir_remove (dir, file_name);
		dir_close(dir);
		
	}
	else	// inode is for directory
	{
		
		if (inode_get_inumber(inode) == cluster_to_sector(ROOT_DIR_CLUSTER)) return false;
		struct dir *dir_inode = dir_open(inode);
		bool not_empty;
		char *name = malloc(NAME_MAX + 1);


		not_empty = dir_readdir(dir_inode, name);
		if (strcmp(name, ".") == 0) 
		{
			not_empty = dir_readdir(dir_inode,name);
			
		}	
		if (strcmp(name, "..") == 0) 
		{
			not_empty = dir_readdir(dir_inode,name);
			
		}	

		

		if (!not_empty) 
		{
			
			success = dir_remove(dir, file_name);
		}
		else 
		{
			
			dir_close(dir_inode);
		}	

		free(name);
		dir_close(dir);
		
	}
	free(file_name);
	palloc_free_page(copy);
	
	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	if (!dir_create (cluster_to_sector(ROOT_DIR_CLUSTER), 16))
		PANIC ("root directory creation failed");
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

bool
filesys_create_dir (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	char *copy = palloc_get_page(PAL_ZERO);
	if (copy == NULL) return false;
	strlcpy(copy, name, strlen(name)+1);



	char *file_name = malloc(NAME_MAX + 1);
	struct dir *dir = dir_parse(copy, file_name);
	if (strlen(file_name) == 0) return false;
	

	cluster_t inode_cluster = fat_create_chain(0);
	if (inode_cluster != 0 ) inode_sector = cluster_to_sector(inode_cluster);

	bool success = (dir != NULL
			&& inode_cluster
			&& inode_create (cluster_to_sector(inode_cluster), initial_size, 0)
			&& dir_add (dir, file_name, inode_sector));
			
	if (!success && inode_sector != 0)
	{
		fat_remove_chain(inode_cluster, 0);
		dir_close (dir);
		palloc_free_page(copy);
		free(file_name);
		return success;
	}
	else
	{
		struct inode *new_inode = inode_open(inode_sector);
		struct dir *new_dir = dir_open(new_inode);

		dir_add(new_dir, ".", inode_sector);
		dir_add(new_dir, "..", dir_inode_sector(dir));

		dir_close(dir);
		dir_close(new_dir);
		palloc_free_page(copy);
		free(file_name);

		
		return success;
	}	
}