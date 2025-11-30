import {Configuration} from "../../../gene/Configuration";
import {Libg} from "../../../libs/Libg";
import {LogicCharacterData} from "../../data/LogicCharacterData";
import {GameObject} from "./GameObject";
import {LogicCharacterClient} from "./LogicCharacterClient";

const Character_updateHealthBar = new NativeFunction(
    Libg.offset(0x43864C, 0x3AA8C), 'void', ['pointer', 'float'] // "hpNumber"
);

const ImpostorMaterial_bind = new NativeFunction(
    Libg.offset(0x465A14, 0x61410), 'void', [ 'pointer', 'int', 'pointer' ]
)

// setaddcolor 0x912FB0 setmulcolor 0x912F2C

const ammoBarOffset = 2544;
const shaderOutlineOffset = 848

export class Character extends GameObject {
    constructor(instance: NativePointer) {
        super(instance)
    }

    getLogicCharacter() {
        return new LogicCharacterClient(
            this.getGameObject().getLogic()
        );
    }

    getCharacterData() {
        return new LogicCharacterData(
            this.instance.add(12).readPointer()
        );
    }

    toString() {
        const logicCharacter = this.getLogicCharacter(); // For test

        return `Character(index=${logicCharacter.getPlayerIndex()})`;
    }

    static patch() {
        let self = NULL
        Interceptor.replace(ImpostorMaterial_bind, new NativeCallback((material, type, value) => {
            if (!Configuration.drawOutline) {
                material.add(868).writeInt(5)
            }

            ImpostorMaterial_bind(material, type, value)
        }, 'void', ['pointer', 'int', 'pointer']))

        Interceptor.replace(Character_updateHealthBar, new NativeCallback(function(character, time) {
            Character_updateHealthBar(character, time)

            if (Configuration.showEnemyAmmo) {
                const ammoBar = character.add(ammoBarOffset).readPointer();
                if (!ammoBar.isNull())
                    ammoBar.add(Process.pointerSize).writeU8(1);
            }
        }, 'void', ['pointer', 'float']));
    }
}
