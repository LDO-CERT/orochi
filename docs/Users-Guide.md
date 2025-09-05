## Table of Contents

- [Table of Contents](#table-of-contents)
- [Concepts](#concepts)
- [Login](#login)
- [Plugins](#plugins)
- [Upload Dump](#upload-dump)
- [Executing Plugins](#executing-plugins)
- [Searching](#searching)
- [Comparing plugin results](#comparing-plugin-results)
- [Sharing Dumps](#sharing-dumps)
- [Bookmarks](#bookmarks)
- [Export to MISP](#export-to-misp)
- [Deleting Dumps](#deleting-dumps)
- [YARA](#yara)
- [HEX Viewer](#hex-viewer)

## Concepts

Orochi is built on django framework and provides a collaborative GUI to Volatility framework.
Orochi uses DASK to distribute loads between different machines.

## Login

The GUI is available on port 8000, so if you are running dockers locally: https://localhost

Use sign-up page to register your user and confirm email address through Mailpit platform.

![sign-in](images/001_sign_in.png)
![sign-up](images/002_sign_up.png)
![mailog](images/003_mailhog_mail.png)

## Plugins

Each user can choose which plugins will be executed automatically after uploading a memory dump. If none is selected, user will be able to choose and run any plugin after upload memory dump.

![plugin-selection](animations/plugins.gif)

## Upload Dump

To upload a memory dump just click + button near DUMPS, choose file, set name and operative system about dump.
Wait until dump is loaded and then press create index.
It is possible to choose the color in order to easily distinguish multiple dumps.

To speed up the upload, both raw and zipped dumps are supported.
Password protected zip files are supported as well.

VmWare Snapshots are also supported, when needed both vmem and vmss, just upload zip file containing both.

![home-page](animations/upload.gif)

Large memory dumps can be placed manually in /media/uploads folder and then selected via "Local folder" dropdown in the upload dialog or via management command

![upload-dump-swagger](images/061_upload_local_dump_manage.png)

When upload is completed it is possible to view the details of dump by pressing "i" button close to the memory dump name.
Useful data shown of the uploaded file are md5, sha256, size, filepath where it is stored and the index name.
![dump-info](animations/dump_info.gif)

## Executing Plugins

A list of plugins will be shown after selecting the dump, then it is possible to selecting single plugin and:

- see the result of plugin if it was set to be run automatically
- run the plugin if it was not set to be run automatically
- re-run the plugin if need to pass some additional parameter (like dump flag, or string file)
- Websocket is used to send notifications about plugins execution status

![plugin-main](animations/main.gif)
![plugin-pstree](animations/pstree.gif)

If the plugin ends with an error, a log button will be shown with the relative error.

![plugin-error](images/020_error_log.png)

Plugins will run simultaneously on Dask workers.
By default docker-compose will create for you 2 different worker on the same machine, just to show how to scale. In case you have different machines, you can run workers there and connect to scheduler on main machine.

![dask-status](images/009_dask_status.png)

## Searching

It is possible to perform a full text search through plugin result thanks to DataTable.
The search works also through multiple dumps, if selected.

![result-search](animations/search.gif)

## Comparing plugin results

When 2 dumps are selected it is possible to chose a plugin (that was run on both dumps) and visualize simultaneously the results.
In this case the color chosen during upload of dump is useful to identify different dumps.
There is also a function that performs json diff.

![result-compare](animations/diff.gif)

## Sharing Dumps

It is possible to share dumps and results between users.
This function is present under edit dump.
User that uploads the dump is the owner of dump; when dump is shared, other user can see dump, see plugin results, run/rerun plugins, but cannot delete dump.

![dump-share](images/016_users_share_dump.png)

## Bookmarks

It is possible to bookmark the result of current view, so when find something interesting you can filter out and then add to bookmarks

After press the bookmark button it is possible to set a name for the bookmark, choose an icon picked from [MTG](https://magic.wizards.com/) sets and star it if want this bookmark appear in starred menu.

Then is possible go to bookmarks from admin button and if bookmark is starred it is shown directly in the menu.

Otherwise opening bookmark the menu will show all bookmarks. The bookmark can be a query against multiple dumps.

![bookmarks](animations/bookmarks.gif)

## Export to MISP

It is possible to export single items to MISP.
![dump-share](images/048_misp_export.png)

This is the result in MISP: files and AV signatures will be created as objects connected with a relation.

![dump-share](images/050_misp_export.png)

## Deleting Dumps

Deleting dump function will delete dump and all results of plugins.
![dump-delete](animations/delete.gif)

## YARA

Orochi provides a dedicated section to manage YARA rules that Volatility plugin will use.
![yara-user](images/065_yara_user.png)

Through this page is possible to view all rules previously imported and enabled by admin

![yara-user-manage](images/066_yara_user_manage.png)

At this page user can search for rules and build the custom yara compiled file to be passed to Volatility yara plugin.

Thanks to postgres the fulltext search inside yara rules files is supported.

The user created the yara file can choose if keep it private or make public and available also for other users.
Is it possible to have different yara compiled files, the only one set as default will be used by Volatility yara plugin.

At this point it will be possible to use the Volatility yara plugin and view the results.

![yara-user-results](images/067_yara_user_results.png)

## HEX Viewer

OROCHI support remote HEX View of dumps.
It is possible to browse the memory dump by pressing "\*" button close to the memory dump.

At this point in the page will appear the HEX Viewer that shows the memory address, the hex values and the ascii values.
It is possible browse manually the entire dump, go to a specific offset anb also search for a specific text.

![hex-view](animations/hex.gif)
