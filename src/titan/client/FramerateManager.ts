import {Libg} from "../../libs/Libg";

const FramerateManager_setSegment = new NativeFunction( // "Battle scope"
    Libg.offset(0xC33BE8, 0xBA3D3C), 'void', ['pointer', 'int']
); 

export class FramerateManager {
    static patch() { // Unlock FPS
        Interceptor.replace(FramerateManager_setSegment, new NativeCallback(function(framerateManager, segment) {
            segment = 2;

            FramerateManager_setSegment(framerateManager, segment);
        }, 'void', ['pointer', 'int']));
    }
}
