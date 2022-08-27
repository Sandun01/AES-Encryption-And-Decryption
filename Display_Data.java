public class Display_Data {

    private String encrypted_data;

    Display_Data(String data) {
        this.encrypted_data = data;
    }

    public void displayData() {
        // display encrypted string
        System.out.println("Encrypted Data form Display_Data class: " + this.encrypted_data);
    }

}
