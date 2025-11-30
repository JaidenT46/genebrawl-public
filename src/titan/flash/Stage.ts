import {Libg} from "../../libs/Libg";

const Stage_instance = Libg.offset(0x1042990, 0xF26008);

// Check for offsets in Stage::init (you can find it in GameMain::init by https://service.supercell.net/t?app=laser)

const safeMarginLeftOffset = 84; // 44
const safeMarginRightOffset = 88; // 48
const safeMarginTopOffset = 92; // 52
const safeMarginBottomOffset = 96; // 56

const pointSizeOffset = 7232; // 228 in ARMv7 36.218 (or 324 in ARM64) // updated

const STAGE_336 = 7376; // 336 // updated
const STAGE_340 = 7380; // 340

export class Stage {
    static getInstance(): NativePointer {
        return Stage_instance.readPointer();
    }

    static getSafeMarginTop(): number {
        return this.getInstance().add(safeMarginTopOffset).readInt();
    }

    static getSafeMarginBottom(): number {
        return this.getInstance().add(safeMarginBottomOffset).readFloat();
    }

    static getSafeMarginLeft(): number {
        return this.getInstance().add(safeMarginLeftOffset).readFloat();
    }

    static getSafeMarginRight(): number {
        return this.getInstance().add(safeMarginRightOffset).readFloat();
    }

    static getPointSize(): number {
        return this.getInstance().add(pointSizeOffset).readFloat();
    }

    static getOffset336(): number {
        return this.getInstance().add(STAGE_336).readInt();
    }

    static getOffset340(): number {
        return this.getInstance().add(STAGE_340).readInt();
    }

    static getX(): number {
        const pointSize = Stage.getPointSize() === 0.0 ? 0.1 : Stage.getPointSize();
        return (Stage.getOffset336() - (Stage.getSafeMarginRight() + Stage.getSafeMarginLeft()) / pointSize) * 0.5;
    }

    static getY(): number {
        const pointSize = Stage.getPointSize() === 0.0 ? 0.1 : Stage.getPointSize();
        return (Stage.getOffset340() - (Stage.getSafeMarginBottom() + Stage.getSafeMarginTop()) / pointSize) * 0.5;
    }

    static toString(): string {
        return `Stage(SML=${this.getSafeMarginLeft()}, SMR=${this.getSafeMarginRight()}, SMT=${this.getSafeMarginTop()}, SMB=${this.getSafeMarginBottom()})`;
    }
}