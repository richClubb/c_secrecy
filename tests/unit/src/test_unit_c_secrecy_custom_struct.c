#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdio.h>

#include "c_secrecy.h"

enum Type {
    Int = 0,
    Float,
    String,
};

void test_basic_custom_struct(void)
{
    struct userdata {
        char name[30];
        int id;
    };

    struct userdata rich = {
        "rich", 1
    };

    struct userdata buffer;
    struct userdata ptr;

    int test = sizeof(struct userdata);

    Secret_t *secret = create_secret((uint8_t *)&rich, sizeof(struct userdata));
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    ptr = *(struct userdata *)secret->value;

    CU_ASSERT_NOT_EQUAL(strncmp("rich", ptr.name, 4), 0);
    CU_ASSERT_NOT_EQUAL(ptr.id, 1);

    expose_secret(secret, (uint8_t *)&buffer, sizeof(struct userdata));

    CU_ASSERT_EQUAL(strncmp("rich", buffer.name, 4), 0);
    CU_ASSERT_EQUAL(buffer.id, 1);

    delete_secret(secret);

    return;
}

void test_basic_custom_struct_array(void)
{
    struct userdata {
        char name[30];
        int id;
    };

    struct userdata data[3] = {{"rich", 1}, {"dan", 2}, {"Phil", 3}};
    struct userdata buffer[3];
    struct userdata *ptr;

    int test = sizeof(struct userdata);

    Secret_t *secret = create_secret((uint8_t *)&data, sizeof(struct userdata)*3);
    CU_ASSERT_NOT_EQUAL_FATAL(secret, NULL); // bomb out if this is bad as we can't continue

    ptr = (struct userdata *)secret->value;

    CU_ASSERT_NOT_EQUAL(strncmp("rich", ptr[0].name, 4), 0);
    CU_ASSERT_NOT_EQUAL(ptr[0].id, 1);
    CU_ASSERT_NOT_EQUAL(strncmp("dan", ptr[1].name, 4), 0);
    CU_ASSERT_NOT_EQUAL(ptr[1].id, 2);
    CU_ASSERT_NOT_EQUAL(strncmp("Phil", ptr[2].name, 4), 0);
    CU_ASSERT_NOT_EQUAL(ptr[2].id, 3);

    expose_secret(secret, (uint8_t *)buffer, sizeof(struct userdata)*3);

    CU_ASSERT_EQUAL(strncmp("rich", buffer[0].name, 4), 0);
    CU_ASSERT_EQUAL(buffer[0].id, 1);
    CU_ASSERT_EQUAL(strncmp("dan", buffer[1].name, 4), 0);
    CU_ASSERT_EQUAL(buffer[1].id, 2);
    CU_ASSERT_EQUAL(strncmp("Phil", buffer[2].name, 4), 0);
    CU_ASSERT_EQUAL(buffer[2].id, 3);

    delete_secret(secret);

    return;
}

// genuinely don't know how to do this. Might need to encode things as TLV
// fundamentally this doesn't work and I don't think it can ever work.
// the pointer to name will (may) not be in the same contiguous address space
// I think I must need to use a TLV in this, encode the TLV and store it as the secret
// and then deserialize it.
void test_basic_TLV_dynamic_sized(void)
{

    struct tlv {
        enum Type type;
        int length;
        uint8_t *value;
    };

    uint8_t *data;
    uint8_t *buffer;
    struct tlv *ptr;
    Secret_t *secret;

    data = (uint8_t *)malloc(sizeof(struct tlv) + sizeof(char) * 4);
    CU_ASSERT_NOT_EQUAL_FATAL(data, NULL);

    ptr = (struct tlv*)data;
    ptr->type = String;
    ptr->length = 4;
    strncpy(&ptr->value, "rich", 4);

    secret = create_secret(data, sizeof(struct tlv) + sizeof(char) * 4);

    ptr = (struct tlv*)&secret->value;

    CU_ASSERT_NOT_EQUAL(ptr->type, String);
    CU_ASSERT_NOT_EQUAL(ptr->length, 4);
    CU_ASSERT_NOT_EQUAL(strncmp(&ptr->value, "rich", 4), 0);

    buffer = (uint8_t *)malloc(secret->value_len);
    expose_secret(secret, buffer, secret->value_len);
 
    ptr = (struct tlv*)buffer;

    CU_ASSERT_EQUAL(ptr->type, String);
    CU_ASSERT_EQUAL(ptr->length, 4);
    CU_ASSERT_EQUAL(strncmp(&ptr->value, "rich", 4), 0);

    free(data);
    free(secret);
}

void load_custom_struct_suite(void)
{
    CU_pSuite suite = CU_add_suite("C secrecy custom struct tests", 0, 0);
    CU_add_test(suite, "test of basic custom struct creation and destruction", test_basic_custom_struct);
    CU_add_test(suite, "test of basic custom struct array creation and destruction", test_basic_custom_struct_array);
    CU_add_test(suite, "test of dynamic custom struct creation and destruction", test_basic_TLV_dynamic_sized);
}