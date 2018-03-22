import java.io.*;
import java.util.ArrayList;

public class Main {
    public static void main(String[] str) {

//        System.out.print(Main.byteArrayToInt(new byte[]{0x40, 0x01, 0x00, 0x00}));


        File file = new File("./jt.exe");
        try {
            BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(new File("./j1.exe")));
//            FileOutputStream out = new FileOutputStream(new File("./j1.exe"));
            //
            FileInputStream fileInputStream = new FileInputStream(file);
            BufferedInputStream inputStream = new BufferedInputStream(fileInputStream);

            byte[] buff = new byte[1024];

            ArrayList<Byte> list = new ArrayList<>();


            int len;
            while ((len = inputStream.read(buff)) != -1) {

                out.write(buff, 0, len);

                for(int i = 0 ;i < len;++i) {
                    list.add(buff[i]);

                }

            }
            //PE文件头
            byte[] b = {list.get(63), list.get(62), list.get(61), list.get(60)};
            int opn = byteArrayToInt(b);
            pp(opn, "PE文件头地址：");
            //运行平台
            byte[] b0 = {0x00, 0x00, list.get(opn + 5), list.get(opn + 4)};
            int opn0 = byteArrayToInt(b0);
            pp(opn0, "运行平台：");
            //区块数
            byte[] b1 = {0x00, 0x00, list.get(opn + 7), list.get(opn + 6)};
            int opn1 = byteArrayToInt(b1);
            pp(opn1, "区块数：");
            //时间戳
            byte[] b2 = {list.get(opn + 11), list.get(opn + 10), list.get(opn + 9), list.get(opn + 8)};
            int opn2 = byteArrayToInt(b2);
            pp(opn2, "时间戳：");
            //指向的符号表
            byte[] b3 = {list.get(opn + 15), list.get(opn + 14), list.get(opn + 13), list.get(opn + 12)};
            int opn3 = byteArrayToInt(b3);
            pp(opn3, "指向的符号表：");
            //符号表中符号的个数
            byte[] b4 = {list.get(opn + 19), list.get(opn + 18), list.get(opn + 17), list.get(opn + 16)};
            int opn4 = byteArrayToInt(b4);
            pp(opn4, "符号表中符号的个数：");
            //可选头大小
            byte[] b5 = {0x00, 0x00, list.get(opn + 21), list.get(opn + 20)};
            int opn5 = byteArrayToInt(b5);
            pp(opn5, "可选头大小：");
            //文件属性
            byte[] b6 = {0x00, 0x00, list.get(opn + 23), list.get(opn + 22)};
            int opn6 = byteArrayToInt(b6);
            pp(opn6, "文件属性：");
            /////////////////////////////////////////////////////////////////////////////////
            //数据表开始地址
            int opn7 =  opn + 24 + opn5;
            pp(opn7, "数据表开始地址：");
            //代码占用空间
            byte[] b8 = {list.get(opn + 31), list.get(opn + 30),list.get(opn + 29),list.get(opn + 28)};
            int opn8 = byteArrayToInt(b8);
            pp(opn8, "代码占用空间：");
            //程序入口点
            byte[] b9 = {list.get(opn + 43), list.get(opn + 42),list.get(opn + 41),list.get(opn + 40)};
            int opn9 = byteArrayToInt(b9);
            pp(opn9, "程序入口点：");
            //内存中区块的对齐大小
            byte[] b10 = {list.get(opn + 59), list.get(opn + 58),list.get(opn + 57),list.get(opn + 56)};
            int opn10 = byteArrayToInt(b10);
            pp(opn10, "内存中区块的对齐大小：");
            //装入内存后总大小
            byte[] b11 = {list.get(opn + 83), list.get(opn + 82),list.get(opn + 81),list.get(opn + 80)};
            int opn11 = byteArrayToInt(b11);
            pp(opn11, "装入内存后总大小：");
            //程序首选装载地址
            byte[] b12 = {list.get(opn + 55), list.get(opn + 54),list.get(opn + 53),list.get(opn + 52)};
            int opn12 = byteArrayToInt(b12);
            pp(opn12, "程序首选装载地址：");
            //文件中区块对齐大小
            byte[] b13 = {list.get(opn + 63), list.get(opn + 62),list.get(opn + 61),list.get(opn + 60)};
            int opn13 = byteArrayToInt(b13);
            pp(opn13, "文件中区块对齐大小：");
            //代码块起始RVA
            byte[] b14 = {list.get(opn + 47), list.get(opn + 46),list.get(opn + 45),list.get(opn + 44)};
            int opn14 = byteArrayToInt(b14);
            pp(opn14, "代码块起始RVA：");
            //所有头加区块表的大小
            byte[] b15 = {list.get(opn + 87), list.get(opn + 86),list.get(opn + 85),list.get(opn + 84)};
            int opn15 = byteArrayToInt(b15);
            pp(opn15, "所有头加区块表的大小：");
            //映像校验和
            byte[] b16 = {list.get(opn + 91), list.get(opn + 90),list.get(opn + 89),list.get(opn + 88)};
            int opn16 = byteArrayToInt(b16);
            pp(opn16, "映像校验和：");
            //数据区块起始RVA
            byte[] b17 = {list.get(opn + 51), list.get(opn + 50),list.get(opn + 49),list.get(opn + 48)};
            int opn17 = byteArrayToInt(b17);
            pp(opn17, "数据区块起始RVA：");

            /////数据表
            int ss = opn + 120;
            for (int i = 0; i < 16; ++i) {
                int kk = 0;
                //1
                byte[] b180 ={list.get(ss + (kk+3)), list.get(ss + (kk+2)),list.get(ss + (kk+1)),list.get(ss  )};
                int opn180 = byteArrayToInt(b180);
                //2
                byte[] b181 ={list.get(ss + (kk+7)), list.get(ss + (kk+6)),list.get(ss + (kk+5)),list.get(ss + (kk+4))};
                int opn181 = byteArrayToInt(b181);
                pp(opn180, String.valueOf(i+1)+"表起始地址：");
                pp(opn181, String.valueOf(i+1)+"表尺寸：");
                ss += 8;
            }

            //首个节表地址
            int s = opn7;
            for (int i = 0; i < opn1; ++i) {
                System.out.print("==========================================================\n");
                //节表名
                byte[] b18 = {list.get(s ), list.get(s + 1),list.get(s + 2),list.get(s + 3),list.get(s + 4), list.get(s + 5),list.get(s + 6),list.get(s+7)};
                System.out.print("节表名:" + new String(b18));
                //节区RVA地址
                byte[] b19 = {list.get(s + 15 ), list.get(s + 14),list.get(s + 13),list.get(s + 12)};
                int opn19 = byteArrayToInt(b19);
                pp(opn19, "节区RVA地址：");

                //文件中对齐后的尺寸
                byte[] b20 = {list.get(s + 19 ), list.get(s + 18),list.get(s + 17),list.get(s + 16)};
                int opn20 = byteArrayToInt(b20);
                pp(opn20, "文件中对齐后的尺寸：");

                //在文件中的偏移量
                byte[] b21 = {list.get(s + 23 ), list.get(s + 22),list.get(s + 21),list.get(s + 20)};
                int opn21 = byteArrayToInt(b21);
                pp(opn21, "在文件中的偏移量(文件偏移地址(FOA))：");

                //真实长度
                byte[] b22 = {list.get(s + 11 ), list.get(s + 10),list.get(s + 9),list.get(s + 8)};
                int opn22 = byteArrayToInt(b22);
                pp(opn22, "真实长度：");

                //真实长度
                byte[] b23 = {list.get(s + 39 ), list.get(s + 38),list.get(s + 37),list.get(s + 36)};
                int opn23 = byteArrayToInt(b23);
                pp(opn23, "标识：");
                //每个节表占40字节大小
                s += 40;
            }




            out.close();
            inputStream.close();


        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    private static void pp(int opn11, String s) {
        System.out.print(s + Integer.toHexString(opn11) + "h\n");
    }

    //
    public static int byteArrayToInt(byte[] b) {
        return b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }
}
