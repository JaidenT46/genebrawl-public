import {GameButton} from "../../../titan/flash/gui/GameButton";
import {UserImagesManager} from "../../features/UserImagesManager";

export class ImageButton extends GameButton {
    constructor(fileName: string | NativePointer) {
        if (fileName instanceof NativePointer) {
            super(fileName);
            return;
        }

        super();

        const image = UserImagesManager.getDownloadedImage(fileName);

        if (!image) return;

        image.setScale(1);

        image.setWidth(128);
        image.setHeight(128);

        this.instance.add(516).scptr(fileName);

        this.setMovieClip(image.instance);
    }

    getFileName() {
        return this.instance.add(516).fromsc();
    }
}