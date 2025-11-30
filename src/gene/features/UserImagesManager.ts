import {Libc} from "../../libs/Libc";
import {Path} from "../../titan/Path";
import {DownloadedImage} from "../../titan/flash/DownloadedImage";
import {GUI} from "../../titan/flash/gui/GUI";
import {JSRandom} from "../../utils/JSRandom";
import {Constants} from "../Constants";
import {LocalizationManager} from "../localization";
import {HttpClient} from "./HttpClient";
import {Filesystem} from "./filesystem";

export class UserImagesManager {
    static getDirName() {
        return Path.getUpdatePath() + Constants.USER_IMAGES_DIR;
    }

    static getImages() {
        return Filesystem.readDirectory(UserImagesManager.getDirName());
    }

    static getImageDataByFullPath(imagePath: string) {
        if (!Filesystem.doesFileExist(imagePath)) {
            return null;
        }

        const file = Filesystem.readFile(imagePath);

        return file;
    }

    static getImageData(fileName: string) {
        return UserImagesManager.getImageDataByFullPath(UserImagesManager.getDirName() + fileName); // /data/user/0/gene.brawl.dev/update/image/user_images/image1.png
    }

    static getDownloadedImage(fileName: string) {
        if (!UserImagesManager.getImages().includes(fileName)) {
            return;
        }

        const downloadedImage = new DownloadedImage(Path.getUpdatePath() + Constants.USER_IMAGES_DIR + fileName);

        return downloadedImage;
    }

    static removeImage(fileName: string) {
        const fullpath = UserImagesManager.getDirName() + fileName;

        return Libc.remove(fullpath);
    }

    static async downloadImage(uri: string) { // TODO: rewrite this mess
        const client = new HttpClient();

        const image = await client.sendRequest(uri, "GET", {
            'Accept': 'image/png, image/jpg',
            'User-Agent': `Mozilla/5.0 (Linux; Android 5.0.2; LG-D700 Build/LRX22G) AppleWebKit/533.10 (KHTML, like Gecko)  Chrome/51.0.2044.194 Mobile Safari/601.3`
        });

        if (image.getStatusCode() !== 200) {
            console.error("Error code:", image.getStatusCode());

            GUI.showFloaterText(
                LocalizationManager.getString("USER_IMAGE_MANAGER_ERROR_WHILE_LOADING")
            );
            return;
        }

        const headers = image.getHeaders();

        console.log(headers, headers['Content-Type']);

        if (!headers['Content-Type']) {
            GUI.showFloaterText(
                LocalizationManager.getString("USER_IMAGE_MANAGER_ERROR_WHILE_LOADING")
            );
            return;
        }

        const imageName = JSRandom.getRandomName();

        const fileType = headers['Content-Type'].includes("png") ? "png" : "jpg";

        Filesystem.createDirectoryIfNotExist(UserImagesManager.getDirName());

        Filesystem.writeToFile(UserImagesManager.getDirName() + `user_${imageName}.${fileType}`, image.getBody());

        GUI.showFloaterText(
            LocalizationManager.getString("USER_IMAGE_MANAGER_LOADED_SUCCESSFULLY")
        );

        // if (Debug.getUserImagesScreen()) {
        //     Debug.getUserImagesScreen().repopulateScrollArea()
        // }

        console.log(imageName, fileType);
    }
}