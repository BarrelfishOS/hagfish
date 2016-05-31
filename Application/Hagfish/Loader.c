#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stdint.h>
#include <sys/stat.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DebugPrintErrorLevelLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/ShellLib.h>

#include <Protocol/LoadedImage.h>

#include <multiboot2.h>

#include <Loader.h>
#include <Config.h>

/* Check that the PXE client is in a usable state, with networking configured,
 * and find both our and the server's IP addresses. */
EFI_STATUS
net_config(EFI_PXE_BASE_CODE_PROTOCOL *pxe,
           EFI_IP_ADDRESS *my_ip,
           EFI_IP_ADDRESS *server_ip) {
    DebugPrint(DEBUG_INFO, "PXE loader at %p, revision %x, %a\n",
               (UINT64)pxe,
               pxe->Revision,
               pxe->Mode->Started ? "running" : "stopped");

    if(!pxe->Mode->DhcpAckReceived) {
        DebugPrint(DEBUG_ERROR, "DHCP hasn't completed.\n");
        return EFI_NOT_READY;
    }

    if(pxe->Mode->UsingIpv6) {
        DebugPrint(DEBUG_ERROR, "PXE using IPv6, I can't handle that.\n");
        return EFI_LOAD_ERROR;
    }

    /* Grab the network details. */
    memcpy(my_ip, &pxe->Mode->StationIp, sizeof(EFI_IPv4_ADDRESS));
    DebugPrint(DEBUG_NET,
               "My IP address is %d.%d.%d.%d\n",
               my_ip->v4.Addr[0], my_ip->v4.Addr[1],
               my_ip->v4.Addr[2], my_ip->v4.Addr[3]);

    /* The octets in the DHCP packet are byte-aligned, but those in an
     * EFI_IP_ADDRESS are word-aligned, so we've got to copy by hand. */
    size_t i;
    for(i = 0; i < 4; i++) {
        server_ip->v4.Addr[i]= pxe->Mode->DhcpAck.Dhcpv4.BootpSiAddr[i];
    }
    DebugPrint(DEBUG_NET,
               "BOOTP server's IP address is %d.%d.%d.%d\n",
               server_ip->v4.Addr[0], server_ip->v4.Addr[1],
               server_ip->v4.Addr[2], server_ip->v4.Addr[3]);

    return EFI_SUCCESS;
}

EFI_STATUS
pxe_config_file_name(struct hagfish_loader *loader, char *config_file_name, UINT64 size) {
    EFI_IP_ADDRESS *my_ip = &loader->d.pxe.my_ip;
    snprintf(config_file_name, size, hagfish_config_fmt,
             my_ip->v4.Addr[0], my_ip->v4.Addr[1],
             my_ip->v4.Addr[2], my_ip->v4.Addr[3]);
    return EFI_SUCCESS;
}


EFI_PXE_BASE_CODE_PROTOCOL *
pxe_loader(struct hagfish_loader *loader) {
    EFI_PXE_BASE_CODE_PROTOCOL *pxe;
    EFI_STATUS status;
    DebugPrint(DEBUG_ERROR, "here: %a:%d\n", __FILE__, __LINE__);

    EFI_LOADED_IMAGE_PROTOCOL *image = loader->hagfishImage;

    status= gST->BootServices->OpenProtocol(
                image->DeviceHandle, &gEfiPxeBaseCodeProtocolGuid,
                (void **)&pxe, gImageHandle, NULL,
                EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    DebugPrint(DEBUG_ERROR, "here: %a:%d\n", __FILE__, __LINE__);

    if(EFI_ERROR(status)) {
        AsciiPrint("OpenProtocol: %r\n", status);
        return NULL;
    }

    return pxe;
}

EFI_STATUS
pxe_size_fn(struct hagfish_loader *loader, char *path, UINT64 *size) {
    EFI_PXE_BASE_CODE_PROTOCOL* pxe = loader->d.pxe.pxe;
    EFI_STATUS status;

    /* Get the file size.  Note that even though this call doesn't touch the
     * supplied buffer (argument 3), it still fails if it's null.  Thus the
     * nonsense parameter. */
    status = pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE, (void *) 0x1,
            FALSE, size, NULL, &loader->d.pxe.server_ip, (UINT8 *) path, NULL, TRUE);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Mtftp: %r, %a\n", status,
                pxe->Mode->TftpError.ErrorString);
    }
    return status;
}

EFI_STATUS
pxe_read_fn(struct hagfish_loader *loader,  char *path, UINT64 *size, UINT8 *buffer) {
    EFI_PXE_BASE_CODE_PROTOCOL* pxe = loader->d.pxe.pxe;
    EFI_STATUS status;

    status= pxe->Mtftp(pxe, EFI_PXE_BASE_CODE_TFTP_READ_FILE, buffer,
                       FALSE, size, NULL, &loader->d.pxe.server_ip,
                       (UINT8 *) path, NULL, FALSE);
    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "Mtftp: %r, %a\n",
                   status, pxe->Mode->TftpError.ErrorString);
    }
    return status;
}

EFI_STATUS
pxe_done(struct hagfish_loader *loader) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *image = loader->hagfishImage;

    status= gST->BootServices->CloseProtocol(
                image->DeviceHandle, &gEfiPxeBaseCodeProtocolGuid,
                gImageHandle, NULL);

    if(EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "CloseProtocol: %r\n", status);
        return status;
    }

    return EFI_SUCCESS;
}

EFI_STATUS
pxe_prepare_multiboot_fn(struct hagfish_loader *loader, void **cursor) {
    /* Add the DHCP ack packet. */
    {
        struct multiboot_tag_network *dhcp=
            (struct multiboot_tag_network *)*cursor;

        dhcp->type= MULTIBOOT_TAG_TYPE_NETWORK;
        dhcp->size= sizeof(struct multiboot_tag_network)
                  + sizeof(EFI_PXE_BASE_CODE_PACKET);
        memcpy(&dhcp->dhcpack, &loader->d.pxe.pxe->Mode->DhcpAck,
               sizeof(EFI_PXE_BASE_CODE_PACKET));

        *cursor+= sizeof(struct multiboot_tag_network)
               + sizeof(EFI_PXE_BASE_CODE_PACKET);
    }
    return EFI_SUCCESS;
}

EFI_STATUS
hagfish_loader_pxe_init(struct hagfish_loader *loader) {
    EFI_STATUS status;
    loader->type = HAGFISH_LOADER_PXE;
    loader->read_fn = &pxe_read_fn;
    loader->size_fn = &pxe_size_fn;
    loader->config_file_name_fn = &pxe_config_file_name;
    loader->done_fn = &pxe_done;

    /* Find the PXE service that loaded us. */
    DebugPrint(DEBUG_INFO,
               "Connecting to the PXE service that loaded me.\n");
    loader->d.pxe.pxe = pxe_loader(loader);
    if(!loader->d.pxe.pxe) {
        return RETURN_LOAD_ERROR;
    }

    /* Check network status. */
    status = net_config(loader->d.pxe.pxe, &loader->d.pxe.my_ip, &loader->d.pxe.server_ip);
    return status;
}

/* Functions related to FS loading. */

EFI_STATUS fs_size_fn(struct hagfish_loader *loader, char *path, UINT64 *size) {
    EFI_STATUS status;
    SHELL_FILE_HANDLE file;

    DebugPrint(DEBUG_ERROR, "fs_size_fn(*path=%a, *size=%d): %a:%d\n", path, *size,  __FILE__, __LINE__);

    size_t path_len = strlen(path);
    CHAR16 path_unicode[path_len];
    AsciiStrToUnicodeStr(path, path_unicode);
    for (size_t i = 0; i < path_len; i++) {
        if (path_unicode[i] == '/') {
            path_unicode[i] = '\\';
        }
    }

    CHAR16 *found_file = ShellFindFilePath(path_unicode);
    DebugPrint(DEBUG_INFO, "ShellFindFilePath found: %s from %s\n", found_file, path_unicode);

    if (!found_file) {
        DebugPrint(DEBUG_INFO, "File not found: %s\n", path_unicode);
        return EFI_LOAD_ERROR;
    }


    status = ShellOpenFileByName(found_file, &file, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "ShellOpenFileByName failed: %d\n", status);
        return EFI_LOAD_ERROR;
    }

    status = ShellGetFileSize(file, size);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "ShellGetFileSize failed: %d\n", status);
        return EFI_LOAD_ERROR;
    }

    status = ShellCloseFile(&file);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "ShellCloseFile failed: %d\n", status);
        return EFI_LOAD_ERROR;
    }

    return EFI_SUCCESS;
}

EFI_STATUS fs_read_fn(struct hagfish_loader *loader, char *path, UINT64 *size,
        UINT8 *buffer) {
    EFI_STATUS status;
    SHELL_FILE_HANDLE file;

    DebugPrint(DEBUG_ERROR, "fs_read_fn(*path=%a, *size=%d): %a:%d\n", path, *size,  __FILE__, __LINE__);

    size_t path_len = strlen(path);
    CHAR16 path_unicode[path_len];
    AsciiStrToUnicodeStr(path, path_unicode);
    for (size_t i = 0; i < path_len; i++) {
        if (path_unicode[i] == '/') {
            path_unicode[i] = '\\';
        }
    }

    CHAR16 *found_file = ShellFindFilePath(path_unicode);
    if (!found_file) {
        DebugPrint(DEBUG_INFO, "File not found: %s\n", path_unicode);
        return EFI_LOAD_ERROR;
    }

    status = ShellOpenFileByName(found_file, &file, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "ShellOpenFileByName failed: %d\n", status);
        return EFI_LOAD_ERROR;
    }

    status = ShellReadFile(file, size, buffer);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "ShellReadFile failed: %d\n", status);
        return EFI_LOAD_ERROR;
    }

    status = ShellCloseFile(&file);
    if (EFI_ERROR(status)) {
        DebugPrint(DEBUG_ERROR, "ShellCloseFile failed: %d\n", status);
        return EFI_LOAD_ERROR;
    }

    return EFI_SUCCESS;
}

EFI_STATUS fs_multiboot_perpare_fn(struct hagfish_loader *loader, void **cursor) {
    return EFI_SUCCESS;
}

EFI_STATUS fs_config_file_name_fn(struct hagfish_loader *loader,
        char *config_file_name, UINT64 size) {
    DebugPrint(DEBUG_ERROR, "here: %a:%a:%d\n", __FILE__, __FUNCTION__, __LINE__);
    // TODO: Get this from parameter!
    memset(config_file_name, 0, size);
    snprintf(config_file_name, size, "hagfish.cfg");
    DebugPrint(DEBUG_ERROR, "here: %a:%a:%d config_file_name=%a\n", __FILE__, __FUNCTION__, __LINE__, config_file_name);
    return EFI_SUCCESS;
}

EFI_STATUS fs_done_fn(struct hagfish_loader *loader) {
    return EFI_SUCCESS;
}

EFI_STATUS
hagfish_loader_fs_init(struct hagfish_loader *loader, CHAR16 *image) {
    DebugPrint(DEBUG_ERROR, "here: %a:%d\n", __FILE__, __LINE__);
    loader->done_fn = &fs_done_fn;
    loader->prepare_multiboot_fn = &fs_multiboot_perpare_fn;
    loader->read_fn = &fs_read_fn;
    loader->size_fn = &fs_size_fn;
    loader->config_file_name_fn = &fs_config_file_name_fn;
    loader->type = HAGFISH_LOADER_FS;

    return EFI_SUCCESS;
}




