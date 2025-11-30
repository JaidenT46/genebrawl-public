import {Libg} from "../libs/Libg";
import {MovieClip} from "./flash/MovieClip";

const ResourceManager_getMovieClip = new NativeFunction( // "bad_conection_icon"
    Libg.offset(0xA217EC, 0x96B444), 'pointer', ['pointer', 'pointer']
);

export class ResourceManager {
    static getMovieClip(fileName: string, exportName: string): MovieClip {
        return new MovieClip(
            ResourceManager_getMovieClip(fileName.ptr(), exportName.ptr())
        );
    }
}